"""The diagnosis engine is pure logic: feed it check results, assert on the verdict."""

from nettriage.diagnosis import diagnose
from nettriage.models import CheckResult, Report, Status
from nettriage.util import parse_target


def make(target="https://shop.example", **checks) -> Report:
    report = Report(id="t", target=parse_target(target), started_at="now", resolved_ip="203.0.113.10")
    defaults = {
        "dns": (Status.OK, {"a": ["203.0.113.10"], "error_kind": None, "resolver": "10.0.0.53"}),
        "ping": (Status.OK, {"sent": 5, "received": 5, "loss_pct": 0.0, "rtt": {"min": 1, "avg": 2, "max": 3, "jitter": 0.5}}),
        "mtr": (Status.OK, {"hops": [{"ttl": 1, "ip": "203.0.113.10", "loss_pct": 0}], "reached": True}),
        "mtu": (Status.OK, {"measurable": True, "path_mtu": 1500, "blackhole": False}),
        "ports": (Status.OK, {"primary": {"port": report.target.port, "state": "open", "note": ""}}),
        "tls": (Status.OK, {"handshake_ok": True, "protocol": "TLSv1.3", "error_kind": None}),
        "http": (Status.OK, {"status_code": 200, "error_kind": None, "timing_ms": {"first_byte": 80}}),
    }
    for cid, (status, details) in {**defaults, **checks}.items():
        report.checks.append(CheckResult(cid, cid, status, f"{cid} summary", details))
    diagnose(report)
    return report


def codes(report):
    return [f.code for f in report.findings]


def test_healthy():
    r = make()
    assert r.overall == Status.OK and not r.findings
    assert r.headline == "Everything checks out: DNS resolves fine, TCP 443 is open, the TLS handshake succeeds (TLSv1.3) and the server answers HTTP 200."


def test_expired_certificate_reads_like_the_brief():
    r = make(
        tls=(Status.FAIL, {"handshake_ok": True, "protocol": "TLSv1.2", "error_kind": "cert_expired", "reason": "the certificate is expired"}),
        http=(Status.OK, {"status_code": 200, "error_kind": None, "timing_ms": {"first_byte": 80}}),
    )
    assert r.overall == Status.FAIL
    assert r.headline == "DNS resolves fine, TCP 443 is open, but the TLS handshake fails because the certificate is expired."
    assert codes(r) == ["TLS_CERT_EXPIRED"]


def test_first_broken_layer_wins():
    """A dead port must not be reported as a TLS or HTTP problem."""
    r = make(
        ports=(Status.FAIL, {"primary": {"port": 443, "state": "closed", "note": "RST"}}),
        tls=(Status.SKIP, {}),
        http=(Status.SKIP, {}),
    )
    assert codes(r) == ["TCP_PORT_CLOSED"]
    assert r.headline.startswith("DNS resolves fine, but TCP 443 is closed")


def test_nxdomain():
    r = make(dns=(Status.FAIL, {"error_kind": "nxdomain", "status": "NXDOMAIN", "resolver": "10.0.0.53"}), ports=(Status.SKIP, {}), tls=(Status.SKIP, {}), http=(Status.SKIP, {}), ping=(Status.SKIP, {}), mtr=(Status.SKIP, {}), mtu=(Status.SKIP, {}))
    assert codes(r) == ["DNS_NXDOMAIN"]
    assert "does not exist (NXDOMAIN)" in r.headline


def test_filtered_port_on_live_host_blames_firewall():
    r = make(ports=(Status.FAIL, {"primary": {"port": 443, "state": "filtered", "note": "no reply"}}), tls=(Status.SKIP, {}), http=(Status.SKIP, {}))
    assert "firewall" in r.headline and codes(r) == ["TCP_PORT_FILTERED"]


def test_filtered_port_on_dead_host_names_the_last_hop():
    r = make(
        ports=(Status.FAIL, {"primary": {"port": 443, "state": "filtered", "note": "no reply"}}),
        ping=(Status.WARN, {"sent": 5, "received": 0, "loss_pct": 100.0, "rtt": None}),
        mtr=(Status.WARN, {"hops": [{"ttl": 1, "ip": "10.0.0.1", "loss_pct": 0}, {"ttl": 2, "ip": "198.51.100.7", "loss_pct": 0}, {"ttl": 3, "ip": None, "loss_pct": 100}], "reached": False}),
        tls=(Status.SKIP, {}),
        http=(Status.SKIP, {}),
    )
    assert "unreachable" in r.headline and "hop 2 (198.51.100.7)" in r.headline


def test_blocked_ping_alone_is_not_a_fault():
    r = make(ping=(Status.WARN, {"sent": 5, "received": 0, "loss_pct": 100.0, "rtt": None}))
    assert r.overall == Status.OK
    assert codes(r) == ["ICMP_BLOCKED"]


def test_mtu_blackhole_explains_a_stalled_download():
    r = make(
        "http://files.example",
        mtu=(Status.WARN, {"measurable": True, "path_mtu": 1000, "blackhole": True, "largest_payload": 972}),
        tls=(Status.SKIP, {}),
        http=(Status.FAIL, {"status_code": 200, "error_kind": "stalled", "reason_text": "the body never arrived"}),
    )
    assert codes(r)[0] == "MTU_BLACKHOLE"
    assert "path-MTU black hole" in r.headline and "1000 bytes" in r.headline
    assert "HTTP_STALLED" not in codes(r)  # one root cause, not two


def test_small_mtu_without_symptoms_is_only_a_warning():
    r = make(mtu=(Status.WARN, {"measurable": True, "path_mtu": 1400, "blackhole": True, "largest_payload": 1372}))
    assert r.overall == Status.WARN and codes(r) == ["MTU_BLACKHOLE_SUSPECTED"]


def test_http_500_is_an_application_problem():
    r = make(http=(Status.FAIL, {"status_code": 503, "error_kind": "server_error", "timing_ms": {"first_byte": 10}}))
    assert "the network is fine" in r.headline and codes(r) == ["HTTP_5XX"]


def test_local_resolver_failure_continues_with_public_dns():
    r = make(dns=(Status.FAIL, {"error_kind": "local_resolver", "status": "SERVFAIL", "resolver": "10.0.0.53"}))
    assert r.overall == Status.FAIL and codes(r) == ["DNS_LOCAL_RESOLVER"]
    assert r.headline.startswith("Your configured DNS server cannot resolve shop.example")
