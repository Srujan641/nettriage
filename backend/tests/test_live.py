"""End-to-end runs against the real internet. Deselect with: pytest -m 'not network'."""

import pytest

from nettriage.engine import run_diagnosis
from nettriage.models import Status

pytestmark = pytest.mark.network
FAST = ("traceroute", "mtr", "mtu", "ping")


def test_healthy_site():
    r = run_diagnosis("https://www.cloudflare.com", skip=FAST)
    assert r.check("dns").status == Status.OK and r.check("ports").status == Status.OK
    assert r.check("tls").details["handshake_ok"] and r.check("http").details["status_code"] in (200, 301, 302, 403)


def test_expired_certificate():
    r = run_diagnosis("https://expired.badssl.com", skip=FAST)
    assert r.overall == Status.FAIL and r.findings[0].code == "TLS_CERT_EXPIRED"
    assert "DNS resolves fine, TCP 443 is open, but the TLS handshake fails because the certificate expired" in r.headline


def test_wrong_host_certificate():
    r = run_diagnosis("https://wrong.host.badssl.com", skip=FAST)
    assert r.findings[0].code == "TLS_HOSTNAME_MISMATCH"


def test_closed_port():
    r = run_diagnosis("http://localhost:9", skip=FAST)
    assert r.findings[0].code == "TCP_PORT_CLOSED"
