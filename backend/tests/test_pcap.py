import struct

import pytest
from conftest import checksum_free_ip as ip
from conftest import lab_capture, tcp, udp, write_pcap

from nettriage.pcap import PcapError, parse_pcap

C, S = "10.0.0.10", "10.0.0.20"
SYN, RST, PSH, ACK = 0x02, 0x04, 0x08, 0x10


def dns_query(txid: int, name: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def problems(result, kind=None):
    return [i for i in result["insights"] if i["severity"] == "problem" and (kind is None or i["kind"] == kind)]


def test_rejects_non_capture(tmp_path):
    f = tmp_path / "x.pcap"
    f.write_bytes(b"this is not a packet capture at all....")
    with pytest.raises(PcapError):
        parse_pcap(f)


def test_unanswered_dns_queries(tmp_path):
    f = write_pcap(tmp_path / "dns.pcap", [(t, ip(C, S, 17, udp(40000, 53, dns_query(7, "app.example.com")))) for t in (0, 3, 6)])
    r = parse_pcap(f)
    assert r["packets"][0]["proto"] == "DNS" and "A app.example.com" in r["packets"][0]["info"]
    (hit,) = problems(r, "dns")
    assert "3 DNS queries for app.example.com" in hit["text"] and hit["packets"] == [1, 2, 3]


def test_dns_nxdomain(tmp_path):
    query = dns_query(9, "ghost.example.com")
    reply = bytearray(query)
    reply[2:4] = struct.pack("!H", 0x8183)  # response, rcode 3
    f = write_pcap(tmp_path / "nx.pcap", [(0, ip(C, S, 17, udp(40000, 53, query))), (0.01, ip(S, C, 17, udp(53, 40000, bytes(reply))))])
    (hit,) = problems(parse_pcap(f), "dns")
    assert "NXDOMAIN" in hit["text"]


def test_closed_port(tmp_path):
    f = write_pcap(tmp_path / "closed.pcap", [(0, ip(C, S, 6, tcp(50000, 443, 100, 0, SYN))), (0.001, ip(S, C, 6, tcp(443, 50000, 0, 101, RST | ACK)))])
    (hit,) = problems(parse_pcap(f), "tcp")
    assert "port is closed" in hit["text"]


def test_filtered_port(tmp_path):
    f = write_pcap(tmp_path / "filtered.pcap", [(t, ip(C, S, 6, tcp(50000, 443, 100, 0, SYN))) for t in (0, 1, 3)])
    r = parse_pcap(f)
    (hit,) = problems(r, "tcp")
    assert "3 SYNs" in hit["text"] and "no reply" in hit["text"]
    assert "retransmission" in r["packets"][1]["tags"]


def test_reset_after_request(tmp_path):
    get = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    f = write_pcap(
        tmp_path / "rst.pcap",
        [
            (0.000, ip(C, S, 6, tcp(50000, 8080, 100, 0, SYN))),
            (0.001, ip(S, C, 6, tcp(8080, 50000, 900, 101, SYN | ACK))),
            (0.002, ip(C, S, 6, tcp(50000, 8080, 101, 901, ACK))),
            (0.003, ip(C, S, 6, tcp(50000, 8080, 101, 901, PSH | ACK, get))),
            (0.004, ip(S, C, 6, tcp(8080, 50000, 901, 101 + len(get), RST | ACK))),
        ],
    )
    r = parse_pcap(f)
    assert r["packets"][3]["proto"] == "HTTP"
    (hit,) = problems(r, "tcp")
    assert "GET / HTTP/1.1" in hit["text"] and "resets the connection" in hit["text"] and hit["packets"] == [2, 4, 5]


def test_tls_alert_decoding(tmp_path):
    alert = bytes([21, 3, 1, 0, 2, 2, 70])  # fatal protocol_version
    f = write_pcap(tmp_path / "alert.pcap", [(0, ip(S, C, 6, tcp(443, 50000, 1, 1, PSH | ACK, alert)))])
    row = parse_pcap(f)["packets"][0]
    assert row["proto"] == "TLS" and row["info"] == "Alert (fatal: protocol_version)"


# ---- the recorded lab captures: the analyser must find each planted fault ----


def test_lab_baseline_has_no_problems():
    assert problems(parse_pcap(lab_capture("00-baseline"))) == []


def test_lab_dns_timeout():
    hits = problems(parse_pcap(lab_capture("01-dns-failure")), "dns")
    assert hits and "never get a response" in hits[0]["text"]


def test_lab_tcp_reset():
    hits = problems(parse_pcap(lab_capture("02-tcp-reset")), "tcp")
    assert any("GET / HTTP/1.1" in h["text"] and "10.77.0.30" in h["text"] for h in hits)


def test_lab_tls_version_mismatch():
    hits = problems(parse_pcap(lab_capture("03-tls-version-mismatch")), "tls")
    assert "offers TLS 1.2 and TLS 1.3" in hits[0]["text"] and "protocol_version" in hits[0]["text"]


def test_lab_mtu_blackhole_from_both_vantage_points():
    client = problems(parse_pcap(lab_capture("04-mtu-blackhole")), "mtu")
    assert any("path-MTU black hole" in h["text"] for h in client)
    router = problems(parse_pcap(lab_capture("04-mtu-blackhole", "r2.pcap")))
    assert any("come in and never leave" in h["text"] for h in router)
    assert any("retransmits" in h["text"] for h in router)
