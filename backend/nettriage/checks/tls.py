"""TLS handshake and certificate inspection (openssl s_client + per-version probing)."""

from __future__ import annotations

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone

from ..models import CheckResult, Status
from ..util import have, run
from .base import Context

VERIFY_CODES = {
    9: "cert_not_yet_valid",
    10: "cert_expired",
    18: "self_signed",
    19: "untrusted_chain",
    20: "untrusted_chain",
    21: "untrusted_chain",
    62: "hostname_mismatch",
    64: "hostname_mismatch",
}
_VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def probe_version(ip: str, port: int, sni: str | None, name: str, timeout: float) -> bool | None:
    """True = server accepts this TLS version, False = refuses it, None = could not tell."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # let legacy versions be offered at all
        except ssl.SSLError:
            pass
        ctx.minimum_version = ctx.maximum_version = _VERSIONS[name]
    except (ValueError, ssl.SSLError):
        return None
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw, ctx.wrap_socket(raw, server_hostname=sni):
            return True
    except ssl.SSLError as exc:
        text = str(exc).upper()
        if "NO_PROTOCOLS_AVAILABLE" in text or "NO_CIPHERS_AVAILABLE" in text:
            return None  # our own TLS library cannot speak this version
        return False
    except (ConnectionResetError, BrokenPipeError):
        return False
    except OSError:
        return None


def _parse_cert(pem: str) -> dict:
    fields = run(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-startdate", "-enddate", "-serial", "-fingerprint", "-sha256"],
        stdin=pem,
    )
    text = run(["openssl", "x509", "-noout", "-text"], stdin=pem).output
    cert: dict = {"_evidence": fields}

    def grab(key: str) -> str | None:
        m = re.search(rf"^{key}\s*=\s*(.+)$", fields.output, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else None

    cert["subject"] = grab("subject")
    cert["issuer"] = grab("issuer")
    cert["serial"] = grab("serial")
    cert["sha256"] = grab("sha256 fingerprint")
    m = re.search(r"CN\s*=\s*([^,/\n]+)", cert["subject"] or "")
    cert["common_name"] = m.group(1).strip() if m else None
    m = re.search(r"(?:O|CN)\s*=\s*([^,/\n]+)", cert["issuer"] or "")
    cert["issuer_name"] = m.group(1).strip() if m else None
    for key, src in (("not_before", "notBefore"), ("not_after", "notAfter")):
        raw = grab(src)
        try:
            dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            cert[key] = dt.isoformat()
        except (TypeError, ValueError):
            cert[key] = None
    cert["san"] = re.findall(r"DNS:([^,\s]+)", text) + re.findall(r"IP Address:([^,\s]+)", text)
    m = re.search(r"Public-Key: \((\d+) bit\)", text)
    cert["key_bits"] = int(m.group(1)) if m else None
    m = re.search(r"Signature Algorithm: (\S+)", text)
    cert["signature_algorithm"] = m.group(1) if m else None
    cert["self_signed"] = bool(cert["subject"]) and cert["subject"] == cert["issuer"]
    if cert["not_after"]:
        cert["days_left"] = (datetime.fromisoformat(cert["not_after"]) - datetime.now(timezone.utc)).days
    return cert


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.lower().rstrip(".")
    try:
        want_ip = ipaddress.ip_address(host)
        return any(_same_ip(want_ip, n) for n in names)
    except ValueError:
        pass
    for name in names:
        name = name.lower().rstrip(".")
        if name == host:
            return True
        if name.startswith("*.") and "." in host and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _same_ip(want, candidate: str) -> bool:
    try:
        return ipaddress.ip_address(candidate) == want
    except ValueError:
        return False


# openssl s_client prints session secrets after a successful handshake. Reports keep the
# command output as evidence, so these are removed before anything is stored or shown.
_SECRET_LINE = re.compile(r"^(\s*(?:Master-Key|Session-ID|Session-ID-ctx|Resumption PSK|PSK identity|PSK|TLS session ticket lifetime hint)\s*:).*$", re.M)
_TICKET_BLOCK = re.compile(r"(TLS session ticket:\n)(?:\s*[0-9a-f]{4} - .*\n)+", re.I)


def redact_secrets(output: str) -> str:
    output = _TICKET_BLOCK.sub(r"\1    [redacted]\n", output)
    return _SECRET_LINE.sub(r"\1 [redacted]", output)


def _s_client(argv: list[str], timeout: float):
    rec = run(argv, timeout=timeout)
    rec.output = redact_secrets(rec.output)
    return rec


def check_tls(ctx: Context) -> CheckResult:
    res = CheckResult("tls", "TLS handshake and certificate")
    t = ctx.target
    if not have("openssl"):
        res.summary = "openssl is not installed."
        return res

    argv = ["openssl", "s_client", "-connect", f"{ctx.ip}:{t.port}", "-showcerts"]
    argv += ["-verify_ip", t.host] if t.is_ip else ["-servername", t.host, "-verify_hostname", t.host]
    if ctx.tls_max == "1.2":
        argv.append("-no_tls1_3")
    elif ctx.tls_max == "1.1":
        argv += ["-no_tls1_3", "-no_tls1_2"]
    # Behave like a current browser: TLS 1.2 is the floor (RFC 8996 retired 1.0 and 1.1).
    # Whether the server still speaks older versions is measured separately below.
    rec = _s_client(argv + ["-min_protocol", "TLSv1.2"], timeout=ctx.timeout + 5)
    if re.search(r"unknown option|usage:", rec.output[:400], re.IGNORECASE):  # e.g. LibreSSL
        rec = _s_client(argv, timeout=ctx.timeout + 5)
    else:
        argv += ["-min_protocol", "TLSv1.2"]
    res.commands.append(rec)
    out = rec.output

    m = re.search(r"New, (TLSv[\d.]+), Cipher is (\S+)", out) or re.search(
        r"Protocol\s*:\s*(TLSv[\d.]+)[\s\S]*?Cipher\s*:\s*(\S+)", out
    )
    protocol, cipher = (m.group(1), m.group(2)) if m else (None, None)
    if protocol == "TLSv1":
        protocol = "TLSv1.0"
    pems = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", out)
    handshake_ok = bool(protocol and pems) and cipher not in ("0000", "(NONE)")

    sni = None if t.is_ip else t.host
    # One at a time, so the probes stay easy to follow in a packet capture.
    probed = []
    for v in _VERSIONS:
        result = probe_version(ctx.ip, t.port, sni, v, ctx.timeout)
        if result is None:  # one retry: a transient network error should not blank the matrix
            result = probe_version(ctx.ip, t.port, sni, v, ctx.timeout)
        probed.append(result)
    versions = dict(zip(_VERSIONS, probed))
    supported = [v for v, ok in versions.items() if ok]

    # Some servers and middleboxes choke on the large ClientHello that post-quantum key
    # shares produce (it no longer fits one packet). If the handshake died but the server
    # demonstrably speaks TLS, retry with classical key-exchange groups only.
    pq_intolerant = False
    died_early = rec.timed_out or bool(re.search(r"connection reset|errno=(54|104)|read 0 bytes", out, re.IGNORECASE))
    if not handshake_ok and not ctx.tls_max and (died_early or versions.get("TLSv1.2") or versions.get("TLSv1.3")):
        for _attempt in range(2):
            retry = _s_client(argv + ["-groups", "X25519:P-256:P-384"], timeout=ctx.timeout + 5)
            m2 = re.search(r"New, (TLSv[\d.]+), Cipher is ([A-Z0-9][\w-]+)", retry.output)
            pems2 = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----", retry.output)
            if m2 and pems2 and m2.group(2) != "0000":
                res.commands.append(retry)
                rec, out, pems, handshake_ok, pq_intolerant = retry, retry.output, pems2, True, True
                protocol, cipher = m2.group(1), m2.group(2)
                break
            if retry.timed_out or retry.duration_ms > 3000:
                break  # a slow failure will not get better; do not make the user wait twice

    res.details = {
        "pq_intolerant": pq_intolerant,
        "handshake_ok": handshake_ok,
        "protocol": protocol,
        "cipher": cipher,
        "versions": versions,
        "client_max": f"TLSv{ctx.tls_max}" if ctx.tls_max else None,
        "chain_length": len(pems),
        "error_kind": None,
    }

    if not handshake_ok:
        res.status = Status.FAIL
        low = out.lower()
        if rec.timed_out:
            kind, why = "timeout", "the server never completed the handshake before the timeout"
        elif re.search(r"alert protocol version|unsupported protocol|no protocols available|version too low", low):
            kind = "version_mismatch"
            ours = f"up to TLSv{ctx.tls_max}" if ctx.tls_max else "TLSv1.2 and TLSv1.3"
            theirs = " and ".join(supported) if supported else "a version this client does not offer"
            why = f"client and server share no TLS version: this client offers {ours}, the server only accepts {theirs}"
        elif "wrong version number" in low or "packet length too long" in low or "record layer failure" in low:
            kind, why = "not_tls", f"port {t.port} is not speaking TLS at all (it looks like plain HTTP or another protocol)"
        elif re.search(r"connection reset|errno=(54|104)", low):
            kind, why = "reset", "the peer reset the TCP connection in the middle of the handshake"
        elif "handshake failure" in low or "no shared cipher" in low:
            kind, why = "handshake_failure", "client and server could not agree on a cipher suite or parameters"
        elif re.search(r"connect:errno|connection refused", low):
            kind, why = "refused", "the TCP connection could not be established"
        else:
            # A version mismatch can also surface as a bare EOF; the probe matrix settles it.
            modern = [versions.get("TLSv1.2"), versions.get("TLSv1.3")]
            if supported and not any(modern):
                kind = "version_mismatch"
                why = f"the server only accepts {' and '.join(supported)}, which modern clients refuse to use"
            else:
                kind, why = "handshake_failure", "the server closed the connection without completing the handshake"
        res.details["error_kind"] = kind
        res.details["reason"] = why
        res.summary = f"TLS handshake failed: {why}."
        return res

    cert = _parse_cert(pems[0])
    res.commands.append(cert.pop("_evidence"))
    res.details["certificate"] = cert

    m = re.search(r"Verify return code: (\d+) \(([^)]*)\)", out)
    verify_code, verify_text = (int(m.group(1)), m.group(2)) if m else (None, None)
    res.details["verify_code"], res.details["verify_text"] = verify_code, verify_text

    names = cert["san"] or ([cert["common_name"]] if cert["common_name"] else [])
    name_ok = hostname_matches(t.host, names)
    res.details["hostname_match"] = name_ok
    days = cert.get("days_left")
    now = datetime.now(timezone.utc)

    kind = None
    if cert["not_after"] and datetime.fromisoformat(cert["not_after"]) < now:
        kind = "cert_expired"
        ago = (now - datetime.fromisoformat(cert["not_after"])).days
        why = f"the certificate expired {ago} day{'s' if ago != 1 else ''} ago ({cert['not_after'][:10]})"
    elif cert["not_before"] and datetime.fromisoformat(cert["not_before"]) > now:
        kind, why = "cert_not_yet_valid", f"the certificate is not valid until {cert['not_before'][:10]}"
    elif not name_ok:
        kind = "hostname_mismatch"
        shown = ", ".join(names[:4]) + (" ..." if len(names) > 4 else "")
        why = f"the certificate is for {shown or 'another name'}, not {t.host}"
    elif verify_code not in (0, None):
        kind = VERIFY_CODES.get(verify_code, "untrusted_chain")
        if kind == "self_signed" or cert["self_signed"]:
            kind, why = "self_signed", "the certificate is self-signed, so no client trusts it by default"
        else:
            why = f"the certificate chain cannot be verified ({verify_text})"

    base = f"Handshake completes with {protocol} ({cipher})"
    if kind:
        res.status = Status.FAIL
        res.details["error_kind"], res.details["reason"] = kind, why
        res.summary = f"{base}, but {why}."
        return res

    res.status = Status.OK
    res.summary = f"{base}; certificate for {cert['common_name'] or names[0]} is valid for {days} more days (issuer: {cert['issuer_name']})."
    warnings = []
    if pq_intolerant:
        warnings.append("pq_intolerant")
        res.summary += " Note: the default (large, post-quantum) ClientHello failed and only a classical one was answered."
    if days is not None and days < 21:
        warnings.append("expiring")
        res.summary += " It expires soon."
    legacy = [v for v in ("TLSv1.0", "TLSv1.1") if versions.get(v)]
    if legacy:
        warnings.append("legacy_protocols")
        res.summary += f" The server still accepts deprecated {' and '.join(legacy)}."
    if warnings:
        res.status = Status.WARN
        res.details["warnings"] = warnings
    return res
