from nettriage.checks.network import _parse_mtr_report, _parse_ping
from nettriage.checks.tls import hostname_matches

MAC_PING = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=6.1 ms

--- 1.1.1.1 ping statistics ---
5 packets transmitted, 4 packets received, 20.0% packet loss
round-trip min/avg/max/stddev = 5.954/6.334/7.100/0.412 ms
"""
LINUX_PING = """PING 10.77.0.20 (10.77.0.20) 56(84) bytes of data.

--- 10.77.0.20 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 1203ms
rtt min/avg/max/mdev = 0.045/0.071/0.120/0.027 ms
"""
LINUX_PING_DEAD = "5 packets transmitted, 0 received, +3 errors, 100% packet loss, time 4100ms\n"
MTR = """Start: 2026-11-11T08:00:00+0000
HOST: client                      Loss%   Snt   Last   Avg  Best  Wrst StDev
  1.|-- 10.77.0.2                  0.0%     5    0.1   0.1   0.1   0.2   0.0
  2.|-- ???                       100.0     5    0.0   0.0   0.0   0.0   0.0
  3.|-- 10.78.0.20                40.0%     5    0.2   0.3   0.2   0.5   0.1
"""


def test_ping_macos():
    d = _parse_ping(MAC_PING)
    assert (d["sent"], d["received"], d["loss_pct"]) == (5, 4, 20.0)
    assert d["rtt"]["avg"] == 6.334


def test_ping_linux():
    d = _parse_ping(LINUX_PING)
    assert (d["sent"], d["received"], d["loss_pct"]) == (5, 5, 0.0)
    assert d["rtt"]["jitter"] == 0.027


def test_ping_all_lost():
    d = _parse_ping(LINUX_PING_DEAD)
    assert d["received"] == 0 and d["loss_pct"] == 100.0 and d["rtt"] is None


def test_mtr_report():
    hops = _parse_mtr_report(MTR)
    assert [h["ttl"] for h in hops] == [1, 3]  # the "???" line has no % sign in mtr's output for silent hops
    assert hops[0]["ip"] == "10.77.0.2" and hops[1]["loss_pct"] == 40.0


def test_hostname_matching():
    assert hostname_matches("example.com", ["example.com"])
    assert hostname_matches("WWW.Example.com", ["*.example.com"])
    assert not hostname_matches("a.b.example.com", ["*.example.com"])  # a wildcard covers one label only
    assert not hostname_matches("example.com", ["*.example.com"])
    assert not hostname_matches("wrong.host.badssl.com", ["*.badssl.com", "badssl.com"])
    assert hostname_matches("10.0.0.1", ["example.com", "10.0.0.1"])


def test_session_secrets_are_redacted_from_evidence():
    from nettriage.checks.tls import redact_secrets

    raw = """SSL-Session:
    Protocol  : TLSv1.2
    Session-ID: 9F3A0C55D1E2B7A4C3D2E1F0A9B8C7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0
    Session-ID-ctx: 
    Master-Key: {key}
    PSK identity: None
    TLS session ticket lifetime hint: 300 (seconds)
    TLS session ticket:
    0000 - 2c 3f 8e 11 a0 5b 77 c1-9d 02 4e 6a 33 f0 18 b2   ,?...[w...Nj3...
    0010 - 7d 55 e1 08 c4 92 3b 6f-a1 4d 2e 90 c7 1f 66 08   }U....;o.M....f.

    Start Time: 1762850000
    Verify return code: 10 (certificate has expired)
""".replace("{key}", "4A1B2C3D" * 12)  # a made-up key, assembled so secret scanners do not flag the test
    clean = redact_secrets(raw)
    assert "4A1B2C3D" not in clean and "9F3A0C55" not in clean and "2c 3f 8e" not in clean
    assert "Master-Key: [redacted]" in clean and "Verify return code: 10" in clean and "Protocol  : TLSv1.2" in clean
