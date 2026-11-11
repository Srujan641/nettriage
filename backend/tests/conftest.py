import struct
from pathlib import Path

import pytest

LAB_CAPTURES = Path(__file__).resolve().parents[2] / "labs" / "captures"


def lab_capture(scenario: str, name: str = "client.pcap") -> Path:
    path = LAB_CAPTURES / scenario / name
    if not path.is_file():
        pytest.skip(f"lab capture {scenario}/{name} not recorded (run labs/run.sh all)")
    return path


def checksum_free_ip(src: str, dst: str, proto: int, payload: bytes, df: bool = True, ident: int = 1) -> bytes:
    import socket

    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000 if df else 0, 64, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return head + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 64240, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> Path:
    """Write IPv4 packets into a classic little-endian pcap with Ethernet framing."""
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, ip in packets:
        frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    path.write_bytes(out)
    return path
