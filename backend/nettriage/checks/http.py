"""HTTP request via curl, pinned to the address the DNS check resolved."""

from __future__ import annotations

import re

from ..models import CheckResult, Status
from ..util import have, run
from .base import Context

_MARK = "__NETTRIAGE__"
_FIELDS = ["http_code", "time_namelookup", "time_connect", "time_appconnect", "time_starttransfer", "time_total", "size_download", "num_redirects", "http_version", "url_effective"]


def check_http(ctx: Context) -> CheckResult:
    res = CheckResult("http", "HTTP response")
    t = ctx.target
    if not have("curl"):
        res.summary = "curl is not installed."
        return res

    budget = max(10.0, ctx.timeout * 3)
    argv = [
        "curl", "-sS", "-k", "-o", "/dev/null", "-D", "-",
        "--connect-timeout", str(int(ctx.timeout)), "--max-time", str(int(budget)),
        "-L", "--max-redirs", "5", "-A", "nettriage/1.0",
        "-w", "\n" + _MARK + "|".join(f"%{{{f}}}" for f in _FIELDS),
    ]  # fmt: skip
    if not t.is_ip:
        argv += ["--resolve", f"{t.host}:{t.port}:{ctx.ip}"]
    if ctx.tls_max and t.scheme == "https":
        argv += ["--tls-max", ctx.tls_max]
    argv.append(t.url)
    rec = run(argv, timeout=budget + 5)
    res.commands.append(rec)

    head, _, tail = rec.output.partition(_MARK)
    values = dict(zip(_FIELDS, tail.splitlines()[0].split("|"))) if tail else {}
    err = re.search(r"curl: \((\d+)\) (.+)", rec.output)
    err_code, err_text = (int(err.group(1)), err.group(2).strip()) if err else (None, "")

    def ms(key: str) -> float | None:
        try:
            return round(float(values[key]) * 1000, 1)
        except (KeyError, ValueError):
            return None

    hops = []
    for block in re.split(r"\r?\n\r?\n", head):
        m = re.match(r"\s*HTTP/(\S+) (\d{3})([^\r\n]*)", block)
        if not m:
            continue
        headers = {}
        for line in block.splitlines()[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        hops.append({"version": m.group(1), "status": int(m.group(2)), "reason": m.group(3).strip(), "headers": headers})
    final = hops[-1] if hops else None
    code = final["status"] if final else 0

    res.details = {
        "url": t.url,
        "status_code": code or None,
        "reason": final["reason"] if final else None,
        "http_version": final["version"] if final else None,
        "server": final["headers"].get("server") if final else None,
        "content_type": final["headers"].get("content-type") if final else None,
        "hsts": bool(final and "strict-transport-security" in final["headers"]),
        "redirects": [{"status": h["status"], "location": h["headers"].get("location")} for h in hops[:-1]],
        "final_url": values.get("url_effective"),
        "bytes": int(float(values.get("size_download") or 0)),
        "timing_ms": {
            "connect": ms("time_connect"),
            "tls": ms("time_appconnect"),
            "first_byte": ms("time_starttransfer"),
            "total": ms("time_total"),
        },
        "curl_exit": err_code,
        "curl_error": err_text,
        "error_kind": None,
    }

    if err_code:
        res.status = Status.FAIL
        got = res.details["bytes"]
        if err_code == 28:
            if code and got == 0:
                kind, why = "stalled", f"the server sent its headers (HTTP {code}) but the body never arrived before the {int(budget)} s timeout"
            elif code or got:
                kind, why = "stalled", f"the transfer froze after {got} bytes and timed out"
            else:
                kind, why = "timeout", f"the server accepted the connection but sent nothing back within {int(budget)} s"
        elif err_code == 56 or "reset" in err_text.lower():
            kind, why = "reset", "the connection was reset by the peer after the request was sent"
        elif err_code == 52:
            kind, why = "empty_reply", "the server closed the connection without sending any response"
        elif err_code in (35, 58, 59, 60):
            kind, why = "tls", f"the TLS layer failed ({err_text})"
        elif err_code == 7:
            kind, why = "connect", "the TCP connection could not be established"
        elif err_code == 18:
            kind, why = "stalled", f"the connection closed early after {got} bytes of the response"
        elif err_code == 47:
            kind, why = "redirect_loop", "the server redirects in a loop"
        else:
            kind, why = "error", err_text or "curl failed"
        res.details["error_kind"], res.details["reason_text"] = kind, why
        res.summary = f"HTTP request failed: {why}."
        return res

    ttfb = res.details["timing_ms"]["first_byte"] or 0
    hop_note = f" after {len(hops) - 1} redirect{'s' if len(hops) > 2 else ''}" if len(hops) > 1 else ""
    res.summary = f"HTTP {code} {final['reason']}".strip() + f"{hop_note}, first byte in {ttfb:.0f} ms over HTTP/{final['version']}."
    if code >= 500:
        res.status = Status.FAIL
        res.details["error_kind"] = "server_error"
    elif code >= 400:
        res.status = Status.WARN
        res.details["error_kind"] = "client_error"
    elif ttfb > 2000:
        res.status = Status.WARN
        res.details["error_kind"] = "slow"
        res.summary += " That is slow."
    else:
        res.status = Status.OK
    return res
