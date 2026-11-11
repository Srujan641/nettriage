"""Turn raw check results into a plain-English verdict.

The checks only measure. This module reasons across layers the way an engineer
would: walk up the stack, name the first layer that breaks, and use the
supporting checks (ping, MTR, path MTU) to explain *why* it breaks.
"""

from __future__ import annotations

from .models import CheckResult, Finding, Report, Status


def _d(check: CheckResult | None) -> dict:
    return check.details if check and check.status != Status.SKIP else {}


def diagnose(report: Report) -> None:
    """Fill in report.findings, report.headline and report.overall."""
    t = report.target
    dns, ping, trace, mtr, mtu = (report.check(i) for i in ("dns", "ping", "traceroute", "mtr", "mtu"))
    ports, tls, http = (report.check(i) for i in ("ports", "tls", "http"))
    findings: list[Finding] = []
    good: list[str] = []  # clauses for layers that work, in stack order
    bad: str | None = None  # the clause for the first layer that breaks

    def add(severity, code, layer, message, evidence="", remedy=""):
        findings.append(Finding(severity, code, layer, message, evidence, remedy))

    # ------------------------------------------------------------------ DNS
    dd = _d(dns)
    kind = dd.get("error_kind")
    if dns and dns.status == Status.FAIL and kind != "local_resolver":
        remedies = {
            "nxdomain": "Check the spelling, then confirm the record exists in the zone (dig +trace). A just-created record can be hidden by negative caching until the SOA minimum TTL passes.",
            "servfail": "The resolver could not get a usable answer from the authoritative servers. Check delegation and DNSSEC: compare `dig +trace` with `dig +cd` (a +cd success means DNSSEC validation is failing).",
            "timeout": "The DNS server never replied. Check it is running and that UDP and TCP port 53 are allowed between you and it; try another resolver to confirm.",
            "unreachable": "Nothing is listening for DNS on that server and port. Check the resolver address and that the DNS service is running.",
            "refused": "The server is up but will not answer this client or zone. Check its allow-query / recursion ACLs.",
            "nodata": "Add an A record, or test this name over IPv6.",
        }
        add("critical", f"DNS_{(kind or 'error').upper()}", "dns", dns.summary, f"dig status: {dd.get('status')}", remedies.get(kind, ""))
        bad = {
            "nxdomain": f"DNS fails: {t.host} does not exist (NXDOMAIN)",
            "servfail": f"DNS fails: the resolver returns SERVFAIL for {t.host}",
            "timeout": f"DNS fails: {dd.get('resolver')} does not answer DNS queries",
            "unreachable": f"DNS fails: nothing is listening for DNS at {dd.get('resolver')}",
            "refused": f"DNS fails: the server refuses the query for {t.host}",
            "nodata": f"DNS fails: {t.host} has no IPv4 address record",
            "error": f"the DNS lookup for {t.host} fails",
        }.get(kind, f"the DNS lookup for {t.host} fails")
    elif kind == "local_resolver":
        add(
            "critical", "DNS_LOCAL_RESOLVER", "dns", dns.summary,
            f"configured resolver: {dd.get('status')}; public resolvers answer normally",
            "Fix or replace the configured resolver (check /etc/resolv.conf, VPN or DHCP-pushed DNS, and any DNS filtering).",
        )  # fmt: skip
        good.append("public DNS resolves the name (your own DNS server does not)")
    elif dns and not t.is_ip:
        good.append("DNS resolves fine")
        if kind == "slow":
            add("warning", "DNS_SLOW", "dns", dns.summary, f"query time {dd.get('query_ms')} ms", "Check resolver load or its upstream latency; a local caching resolver hides this.")

    # ------------------------------------------------------------ supporting
    pd, md, ud = _d(ping), _d(mtr), _d(mtu)
    ping_dead = bool(pd) and pd.get("received") == 0
    primary = _d(ports).get("primary", {})
    tcp_open = primary.get("state") == "open"
    path_end = None  # last hop that answered, when the path never reaches the target
    if md and not md.get("reached"):
        answered = [h for h in md.get("hops", []) if h["ip"]]
        path_end = answered[-1] if answered else None
    td, hd = _d(tls), _d(http)
    blackhole = bool(ud.get("blackhole"))
    stalled = td.get("error_kind") == "timeout" or hd.get("error_kind") in ("stalled", "timeout")

    # ------------------------------------------------------------------ TCP
    if ports and ports.status != Status.SKIP and bad is None:
        port = primary.get("port", t.port)
        if tcp_open:
            good.append(f"TCP {port} is open")
        elif primary.get("state") == "closed":
            bad = f"TCP {port} is closed: the host answers the SYN with a reset, so nothing is accepting connections on that port"
            add(
                "critical", "TCP_PORT_CLOSED", "tcp", f"{report.resolved_ip} actively refuses connections on port {port}.",
                "SYN answered with RST",
                "Check the service is running and bound to this address (ss -ltnp), and that no firewall rule rejects with tcp-reset.",
            )  # fmt: skip
        else:
            if ping_dead and path_end:
                bad = f"the host is unreachable: TCP {port} gets no answer, ping gets no answer, and the path goes quiet after hop {path_end['ttl']} ({path_end['ip']})"
                remedy = f"Traffic dies after {path_end['ip']}. Check the host is up, then routing and ACLs at or just beyond that hop."
            elif ping_dead:
                bad = f"the host looks down or fully firewalled: neither TCP {port} nor ping gets any answer"
                remedy = "Check the host is powered on and its address is right, then firewalls and security groups in between."
            else:
                bad = f"TCP {port} is filtered: the host is alive (it answers ping) but SYNs to that port are silently dropped, which points at a firewall"
                remedy = f"Allow inbound TCP {port} in the host firewall / security group / ACL. A silent drop (no RST) is a DROP rule, not a stopped service."
            add("critical", "TCP_PORT_FILTERED", "tcp", f"No reply to SYN on {report.resolved_ip}:{port}.", primary.get("note", ""), remedy)

    # ------------------------------------------------------------------ TLS
    if tls and tls.status != Status.SKIP and bad is None:
        k = td.get("error_kind")
        why = td.get("reason", "")
        if tls.status != Status.FAIL:
            good.append(f"the TLS handshake succeeds ({td.get('protocol')})")
        elif k == "timeout" and blackhole:
            pass  # explained by the MTU rule below
        else:
            bad = f"the TLS handshake fails because {why}"
            remedies = {
                "version_mismatch": "Enable TLS 1.2 or 1.3 on the server (ssl_protocols / SSLProtocol), or upgrade the client. TLS 1.0 and 1.1 are deprecated (RFC 8996).",
                "reset": "Something tears the connection down when it sees the ClientHello: an IPS, SNI filtering, a proxy with no backend, or a crashing server. Capture on both sides to see which device emits the RST.",
                "not_tls": "Use http:// for this port, or enable TLS on the listener.",
                "handshake_failure": "Compare the offered and accepted cipher suites (openssl s_client -cipher, nmap --script ssl-enum-ciphers).",
                "timeout": "The server accepted TCP but never answered the ClientHello. Check the service is healthy and not overloaded.",
                "cert_expired": "Renew the certificate and reload the server. Automate renewal (ACME) and alert at 30 days.",
                "cert_not_yet_valid": "Check the server clock and the certificate's start date.",
                "hostname_mismatch": "Serve a certificate whose SAN includes this hostname, or fix the SNI / virtual-host mapping.",
                "self_signed": "Install a certificate from a trusted CA, or add this CA to the clients' trust store if it is internal.",
                "untrusted_chain": "Serve the full chain (leaf + intermediates) and make sure the root is in the clients' trust store.",
            }
            add("critical", f"TLS_{(k or 'error').upper()}", "tls", tls.summary, td.get("verify_text") or "", remedies.get(k, ""))
        for w in td.get("warnings", []):
            if w == "expiring":
                add("warning", "TLS_CERT_EXPIRING", "tls", f"The certificate expires in {td['certificate']['days_left']} days.", td["certificate"].get("not_after", ""), "Renew it now and automate renewal.")
            if w == "pq_intolerant":
                add("warning", "TLS_LARGE_HELLO_INTOLERANT", "tls", "The handshake failed with the default ClientHello (which carries post-quantum key shares and no longer fits one packet) and succeeded with classical key exchange only. The server, or a middlebox in front of it, appears to mishandle large ClientHellos.", "openssl s_client fails by default and succeeds with -groups X25519:P-256:P-384", "Update the TLS stack or the load balancer / middlebox in front of it; current browsers send post-quantum hellos by default and may fail or fall back.")
            if w == "legacy_protocols":
                old = [v for v in ("TLSv1.0", "TLSv1.1") if td["versions"].get(v)]
                add("warning", "TLS_LEGACY_PROTOCOLS", "tls", f"The server still accepts {' and '.join(old)}, which {'is' if len(old) == 1 else 'are'} deprecated (RFC 8996).", "", "Disable TLS 1.0/1.1 unless a legacy client truly needs them.")

    # ----------------------------------------------------------------- HTTP
    if http and http.status != Status.SKIP and bad is None:
        k = hd.get("error_kind")
        code = hd.get("status_code")
        if http.status == Status.OK or k == "slow":
            good.append(f"the server answers HTTP {code}")
            if k == "slow":
                add("warning", "HTTP_SLOW", "http", http.summary, f"first byte after {hd['timing_ms']['first_byte']} ms", "The network path is fine; look at the application or its backends.")
        elif k == "client_error":
            good.append(f"the server answers, with HTTP {code}")
            add("warning", "HTTP_4XX", "http", f"The server is reachable and healthy at the network level but answers HTTP {code} {hd.get('reason') or ''}.".strip(), "", "This is an application-level answer (auth, path or permissions), not a network fault.")
        elif k == "server_error":
            bad = f"the server answers HTTP {code}: the network is fine and the application behind it is failing"
            add("critical", "HTTP_5XX", "http", http.summary, "", "Check the application and upstream logs; 502/503/504 usually mean the proxy cannot reach a healthy backend.")
        elif k in ("stalled", "timeout") and blackhole:
            pass
        else:
            bad = f"the HTTP request fails because {hd.get('reason_text')}"
            remedies = {
                "reset": "A RST after the request means a device or the server process killed the connection on purpose: a WAF/IPS rule, a proxy whose backend died, or a crashed worker. Capture on both sides and compare which side sees the RST first.",
                "empty_reply": "The server closed without answering. Check server/proxy logs for a crash or an idle/keepalive timeout mismatch.",
                "timeout": "The server accepted the connection but never replied. Check application health and backend dependencies.",
                "stalled": "The response started and then froze. Check for packet loss, MTU problems, or a backend that hangs mid-response.",
            }
            add("critical", f"HTTP_{(k or 'error').upper()}", "http", http.summary, hd.get("curl_error", ""), remedies.get(k, ""))

    # ------------------------------------------------------------ MTU rules
    if blackhole and stalled and bad is None:
        size = ud.get("path_mtu")
        what = "TLS handshake" if td.get("error_kind") == "timeout" else "HTTP response"
        bad = (
            f"the {what} stalls because of a path-MTU black hole: only packets up to {size} bytes cross the path, "
            "larger ones are dropped, and the ICMP 'fragmentation needed' message that should tell the sender to shrink them never arrives"
        )
        add(
            "critical", "MTU_BLACKHOLE", "network",
            f"Path-MTU black hole: packets larger than {size} bytes are silently dropped. Small exchanges (ping, TCP handshake, the request) work; the large {what} packets do not.",
            f"DF ping of {ud.get('largest_payload')} bytes payload passes, one byte more is lost with no ICMP error",
            "Stop filtering ICMP type 3 code 4 on the path. Until then, clamp TCP MSS on the router (iptables -j TCPMSS --clamp-mss-to-pmtu) or lower the interface MTU on the endpoints.",
        )  # fmt: skip
    elif ud.get("path_mtu") and ud["path_mtu"] < 1500:
        if blackhole:
            add("warning", "MTU_BLACKHOLE_SUSPECTED", "network", mtu.summary, "", "Nothing is failing yet, but large transfers may stall. It can also simply be a filter on large ICMP packets; confirm with a large download.")
        else:
            add("info", "MTU_REDUCED", "network", mtu.summary, "", "Normal for tunnels, PPPoE and VPNs. No action needed while ICMP 'fragmentation needed' keeps flowing.")

    # ------------------------------------------------- loss / latency / ICMP
    if md.get("loss_onset"):
        add("warning", "PACKET_LOSS", "network", mtr.summary, "", "Share the MTR output with whoever operates that hop. Run it from both ends: loss on the return path looks the same from one side.")
    elif pd and 0 < pd.get("loss_pct", 0) < 100:
        add("warning", "PACKET_LOSS", "network", f"Ping shows {pd['loss_pct']:.0f}% packet loss to {report.resolved_ip}.", "", "Repeat with more probes (mtr -c 100) to locate where the loss starts.")
    if ping_dead and tcp_open:
        add("info", "ICMP_BLOCKED", "network", "The host does not answer ping, but TCP works, so ICMP echo is simply being filtered. That is common and not a fault.", "", "")
    if pd.get("rtt") and pd["rtt"]["avg"] > 300:
        add("warning", "HIGH_LATENCY", "network", f"Round-trip time averages {pd['rtt']['avg']:.0f} ms.", "", "Check the MTR table for the hop where latency jumps and stays high.")

    # -------------------------------------------------------------- verdict
    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f.severity])
    report.findings = findings

    def join(parts: list[str]) -> str:
        return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + " and " + parts[-1]

    def cap(text: str) -> str:
        return text[0].upper() + text[1:]

    if bad:
        report.overall = Status.FAIL
        report.headline = cap(f"{', '.join(good)}, but {bad}." if good else f"{bad}.")
    elif any(f.code == "DNS_LOCAL_RESOLVER" for f in findings):
        report.overall = Status.FAIL
        report.headline = f"Your configured DNS server cannot resolve {t.host}, although the name is fine: {join(good)}."
    else:
        warns = [f for f in findings if f.severity == "warning"]
        report.overall = Status.WARN if warns else Status.OK
        lead = "Reachable, with warnings" if warns else "Everything checks out"
        report.headline = f"{lead}: {join(good)}." if good else f"{lead}."
        if warns:
            report.headline += " Worth a look: " + warns[0].message
