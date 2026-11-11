"""Dependency-free packet capture reader and analyser.

Reads pcap and pcapng files (as written by tcpdump or Wireshark), decodes
IPv4 / TCP / UDP / ICMP plus the DNS, TLS and HTTP details that matter for
troubleshooting, and points out the packets that explain a failure.
"""

from __future__ import annotations

import struct
from pathlib import Path

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 40: "handshake_failure",
    42: "bad_certificate", 45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 112: "unrecognized_name", 120: "no_application_protocol",
}  # fmt: skip
TLS_HANDSHAKES = {1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 11: "Certificate", 12: "Server Key Exchange", 14: "Server Hello Done", 16: "Client Key Exchange", 20: "Finished"}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 65: "HTTPS"}
ICMP_NAMES = {(0, 0): "Echo (ping) reply", (8, 0): "Echo (ping) request", (11, 0): "Time-to-live exceeded", (3, 0): "Destination unreachable (network)", (3, 1): "Destination unreachable (host)", (3, 3): "Destination unreachable (port)", (3, 4): "Destination unreachable (fragmentation needed)", (3, 13): "Destination unreachable (administratively filtered)"}
MAX_PACKETS = 5000


class PcapError(ValueError):
    pass


# ------------------------------------------------------------------ file readers


def _read_frames(data: bytes):
    """Yield (timestamp_seconds, linktype, frame_bytes)."""
    if len(data) < 24:
        raise PcapError("File is too short to be a capture.")
    magic = data[:4]
    if magic == b"\x0a\x0d\x0d\x0a":
        yield from _read_pcapng(data)
        return
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6), b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
    if magic not in table:
        raise PcapError("Not a pcap or pcapng file.")
    end, frac = table[magic]
    linktype = struct.unpack(end + "I", data[20:24])[0] & 0xFFFF
    pos = 24
    while pos + 16 <= len(data):
        sec, sub, caplen, _orig = struct.unpack(end + "IIII", data[pos : pos + 16])
        pos += 16
        yield sec + sub / frac, linktype, data[pos : pos + caplen]
        pos += caplen


def _read_pcapng(data: bytes):
    pos, end, links = 0, "<", []
    while pos + 12 <= len(data):
        btype = data[pos : pos + 4]
        if btype == b"\x0a\x0d\x0d\x0a":
            end = "<" if data[pos + 8 : pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
            links = []
        blen = struct.unpack(end + "I", data[pos + 4 : pos + 8])[0]
        if blen < 12:
            break
        body = data[pos + 8 : pos + blen - 4]
        kind = struct.unpack(end + "I", btype)[0]
        if kind == 1:  # interface description
            links.append(struct.unpack(end + "H", body[:2])[0])
        elif kind == 6 and len(body) >= 20:  # enhanced packet
            iface, hi, lo, caplen, _ = struct.unpack(end + "IIIII", body[:20])
            yield ((hi << 32) | lo) / 1e6, links[iface] if iface < len(links) else 1, body[20 : 20 + caplen]
        pos += blen


def _direction(linktype: int, frame: bytes) -> tuple[str, int]:
    """For Linux 'any'-interface captures: ('in' | 'out' | '', interface index)."""
    if linktype == 113 and len(frame) >= 16:
        return ("out" if struct.unpack("!H", frame[0:2])[0] == 4 else "in"), 0
    if linktype == 276 and len(frame) >= 20:
        return ("out" if frame[10] == 4 else "in"), struct.unpack("!I", frame[4:8])[0]
    return "", 0


def _strip_link(linktype: int, frame: bytes) -> tuple[int, bytes]:
    """Return (ethertype, network-layer payload)."""
    if linktype == 1 and len(frame) >= 14:
        etype, off = struct.unpack("!H", frame[12:14])[0], 14
        if etype == 0x8100 and len(frame) >= 18:
            etype, off = struct.unpack("!H", frame[16:18])[0], 18
        return etype, frame[off:]
    if linktype == 113 and len(frame) >= 16:  # Linux cooked capture (tcpdump -i any)
        return struct.unpack("!H", frame[14:16])[0], frame[16:]
    if linktype == 276 and len(frame) >= 20:  # Linux cooked v2
        return struct.unpack("!H", frame[0:2])[0], frame[20:]
    if linktype in (0, 108) and len(frame) >= 4:  # BSD loopback
        return (0x0800 if frame[0] == 2 or frame[3] == 2 else 0x86DD), frame[4:]
    if linktype in (12, 101, 228):
        return 0x0800, frame
    return 0, frame


# ------------------------------------------------------------- protocol decoders


def _dns_name(buf: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels, jumped_to = [], None
    while pos < len(buf) and depth < 10:
        n = buf[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                break
            target = ((n & 0x3F) << 8) | buf[pos + 1]
            if jumped_to is None:
                jumped_to = pos + 2
            pos, depth = target, depth + 1
            continue
        labels.append(buf[pos + 1 : pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    return ".".join(labels) or ".", (jumped_to if jumped_to is not None else pos)


def _decode_dns(buf: bytes) -> dict | None:
    if len(buf) < 12:
        return None
    txid, flags, qd, an = struct.unpack("!HHHH", buf[:8])
    try:
        name, pos = _dns_name(buf, 12) if qd else (".", 12)
        qtype = struct.unpack("!H", buf[pos : pos + 2])[0] if qd else 0
        pos += 4
        answers = []
        if flags & 0x8000:
            for _ in range(an):
                _, pos = _dns_name(buf, pos)
                rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", buf[pos : pos + 10])
                pos += 10
                if rtype == 1 and rdlen == 4:
                    answers.append(".".join(map(str, buf[pos : pos + 4])))
                elif rtype == 5:
                    answers.append("CNAME " + _dns_name(buf, pos)[0])
                pos += rdlen
    except (struct.error, IndexError):
        return None
    return {
        "id": txid,
        "response": bool(flags & 0x8000),
        "rcode": DNS_RCODES.get(flags & 0xF, str(flags & 0xF)),
        "name": name,
        "qtype": DNS_TYPES.get(qtype, str(qtype)),
        "answers": answers,
    }


def _decode_tls(buf: bytes) -> dict | None:
    """Decode the TLS records at the start of a TCP segment."""
    if len(buf) < 5 or buf[0] not in (20, 21, 22, 23) or buf[1] != 3 or buf[2] > 4:
        return None
    out = {"records": [], "alert": None, "sni": None, "offered": [], "selected": None}
    pos = 0
    while pos + 5 <= len(buf) and buf[pos] in (20, 21, 22, 23) and buf[pos + 1] == 3:
        ctype, rlen = buf[pos], struct.unpack("!H", buf[pos + 3 : pos + 5])[0]
        body = buf[pos + 5 : pos + 5 + rlen]
        if ctype == 20:
            out["records"].append("Change Cipher Spec")
        elif ctype == 23:
            out["records"].append("Application Data")
        elif ctype == 21:
            if len(body) == 2 and body[0] in (1, 2):
                desc = TLS_ALERTS.get(body[1], f"alert {body[1]}")
                out["alert"] = {"level": "fatal" if body[0] == 2 else "warning", "description": desc}
                out["records"].append(f"Alert ({out['alert']['level']}: {desc})")
            else:
                out["records"].append("Encrypted Alert")
        elif ctype == 22:
            htype = body[0] if body else 0
            name = TLS_HANDSHAKES.get(htype)
            if name is None or (len(body) >= 4 and int.from_bytes(body[1:4], "big") > 20000):
                out["records"].append("Encrypted Handshake Message")
            else:
                out["records"].append(name)
                if htype in (1, 2):
                    _decode_hello(body, htype == 1, out)
        pos += 5 + rlen
    return out if out["records"] else None


def _decode_hello(body: bytes, client: bool, out: dict) -> None:
    try:
        legacy = struct.unpack("!H", body[4:6])[0]
        pos = 6 + 32
        pos += 1 + body[pos]  # session id
        if client:
            pos += 2 + struct.unpack("!H", body[pos : pos + 2])[0]  # cipher suites
            pos += 1 + body[pos]  # compression methods
        else:
            pos += 3  # chosen cipher + compression
        versions = []
        if pos + 2 <= len(body):
            ext_end = pos + 2 + struct.unpack("!H", body[pos : pos + 2])[0]
            pos += 2
            while pos + 4 <= min(ext_end, len(body)):
                etype, elen = struct.unpack("!HH", body[pos : pos + 4])
                data = body[pos + 4 : pos + 4 + elen]
                if etype == 0 and client and len(data) > 5:
                    out["sni"] = data[5 : 5 + struct.unpack("!H", data[3:5])[0]].decode("ascii", "replace")
                elif etype == 43:
                    raw = data[1:] if client else data
                    versions = [struct.unpack("!H", raw[i : i + 2])[0] for i in range(0, len(raw) - 1, 2)]
                pos += 4 + elen
        names = [TLS_VERSIONS[v] for v in versions if v in TLS_VERSIONS] or [TLS_VERSIONS.get(legacy, hex(legacy))]
        if client:
            out["offered"] = names
        else:
            out["selected"] = names[0]
    except (struct.error, IndexError):
        pass


def _tcp_flags(bits: int) -> list[str]:
    names = [("FIN", 1), ("SYN", 2), ("RST", 4), ("PSH", 8), ("ACK", 16), ("URG", 32)]
    order = ["SYN", "FIN", "RST", "PSH", "ACK", "URG"]
    present = {n for n, b in names if bits & b}
    return [n for n in order if n in present]


# ----------------------------------------------------------------------- parsing


def parse_pcap(path: str | Path, limit: int = MAX_PACKETS) -> dict:
    """Decode a capture into rows plus automatic observations."""
    data = Path(path).read_bytes()
    packets: list[dict] = []
    isn: dict[tuple, int] = {}
    seen_segments: set[tuple] = set()
    t0 = None
    truncated = False

    for ts, linktype, frame in _read_frames(data):
        if len(packets) >= limit:
            truncated = True
            break
        if t0 is None:
            t0 = ts
        etype, ip = _strip_link(linktype, frame)
        direction, ifindex = _direction(linktype, frame)
        row = {"no": len(packets) + 1, "time": round(ts - t0, 6), "src": "", "dst": "", "proto": "", "length": len(frame), "info": "", "tags": [], "dir": direction, "if": ifindex}
        packets.append(row)

        if etype == 0x0806:
            row.update(proto="ARP", info="Address resolution")
            continue
        if etype == 0x86DD:
            row.update(proto="IPv6", info="IPv6 packet (not decoded)")
            continue
        if etype != 0x0800 or len(ip) < 20 or ip[0] >> 4 != 4:
            row.update(proto="OTHER", info=f"ethertype 0x{etype:04x}")
            continue

        ihl = (ip[0] & 0x0F) * 4
        total_len, ip_id, frag = struct.unpack("!HHH", ip[2:8])
        ttl, proto = ip[8], ip[9]
        src, dst = ".".join(map(str, ip[12:16])), ".".join(map(str, ip[16:20]))
        df, mf, frag_off = bool(frag & 0x4000), bool(frag & 0x2000), (frag & 0x1FFF) * 8
        payload = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]
        row.update(src=src, dst=dst, ip={"len": total_len, "id": ip_id, "ttl": ttl, "df": df, "mf": mf, "frag_offset": frag_off})

        if mf or frag_off:
            row["tags"].append("fragment")
            if frag_off:
                row.update(proto="IPv4", info=f"Fragmented IP protocol (proto={proto}, off={frag_off}, ID={ip_id:04x})")
                continue

        if proto == 1 and len(payload) >= 8:
            itype, icode = payload[0], payload[1]
            info = ICMP_NAMES.get((itype, icode), f"ICMP type {itype} code {icode}")
            if itype in (0, 8):
                info += f" id=0x{payload[4:6].hex()} seq={struct.unpack('!H', payload[6:8])[0]} len={len(payload) - 8}"
            if (itype, icode) == (3, 4):
                info += f", next-hop MTU {struct.unpack('!H', payload[6:8])[0]}"
                row["tags"].append("frag-needed")
            row.update(proto="ICMP", info=info, icmp={"type": itype, "code": icode})
            if mf:
                row["info"] += " [first IP fragment]"
        elif proto == 17 and len(payload) >= 8:
            sport, dport = struct.unpack("!HH", payload[:4])
            body = payload[8:]
            row.update(proto="UDP", sport=sport, dport=dport, info=f"{sport} → {dport} Len={len(body)}")
            if 53 in (sport, dport) or 5353 in (sport, dport):
                dns = _decode_dns(body)
                if dns:
                    row["proto"], row["dns"] = "DNS", dns
                    if dns["response"]:
                        tail = (" " + ", ".join(dns["answers"][:3])) if dns["answers"] else ""
                        note = "" if dns["rcode"] == "NOERROR" else f" {dns['rcode']}"
                        row["info"] = f"Standard query response 0x{dns['id']:04x}{note} {dns['qtype']} {dns['name']}{tail}"
                        if dns["rcode"] != "NOERROR":
                            row["tags"].append("dns-error")
                    else:
                        row["info"] = f"Standard query 0x{dns['id']:04x} {dns['qtype']} {dns['name']}"
        elif proto == 6 and len(payload) >= 20:
            sport, dport, seq, ack, off_flags, win = struct.unpack("!HHIIHH", payload[:16])
            hlen = (off_flags >> 12) * 4
            flags = _tcp_flags(off_flags & 0x3F)
            body = payload[hlen:]
            mss = None
            opts, i = payload[20:hlen], 0
            while i < len(opts):
                if opts[i] == 0:
                    break
                if opts[i] == 1:
                    i += 1
                    continue
                if i + 1 >= len(opts) or opts[i + 1] < 2:
                    break
                if opts[i] == 2 and opts[i + 1] == 4:
                    mss = struct.unpack("!H", opts[i + 2 : i + 4])[0]
                i += opts[i + 1]
            flow, rev = (src, sport, dst, dport), (dst, dport, src, sport)
            if "SYN" in flags:
                isn[flow] = seq
            rel_seq = (seq - isn.get(flow, seq)) & 0xFFFFFFFF
            rel_ack = (ack - isn.get(rev, ack)) & 0xFFFFFFFF if "ACK" in flags else 0
            info = f"{sport} → {dport} [{', '.join(flags)}] Seq={rel_seq}"
            if "ACK" in flags:
                info += f" Ack={rel_ack}"
            info += f" Win={win} Len={len(body)}"
            if mss:
                info += f" MSS={mss}"
            row.update(proto="TCP", sport=sport, dport=dport, tcp={"flags": flags, "seq": rel_seq, "ack": rel_ack, "len": len(body), "mss": mss})

            key = (flow, seq, len(body), "SYN" in flags, "FIN" in flags, direction, ifindex)
            if body or "SYN" in flags or "FIN" in flags:
                if key in seen_segments:
                    row["tags"].append("retransmission")
                    info = "[TCP Retransmission] " + info
                seen_segments.add(key)
            if "RST" in flags:
                row["tags"].append("rst")

            tls = _decode_tls(body) if body else None
            if tls:
                row["tls"] = tls
                version = tls["selected"] or (max(tls["offered"]) if tls["offered"] else None)
                row["proto"] = "TLS"
                info = ", ".join(tls["records"])
                if tls["sni"]:
                    info += f" (SNI={tls['sni']})"
                if tls["offered"]:
                    info += f" [offers {', '.join(sorted(tls['offered']))}]"
                if tls["selected"]:
                    info += f" [selects {version}]"
                if tls["alert"]:
                    row["tags"].append("tls-alert")
            elif body[:5] in (b"GET /", b"POST ", b"HEAD ", b"PUT /", b"HTTP/"):
                row["proto"] = "HTTP"
                info = body.split(b"\r\n", 1)[0].decode("ascii", "replace")[:120]
            row["info"] = info
        else:
            row.update(proto=f"IP/{proto}", info=f"IP protocol {proto}")

    return {
        "file": Path(path).name,
        "packet_count": len(packets),
        "truncated": truncated,
        "duration_s": packets[-1]["time"] if packets else 0,
        "protocols": _protocol_counts(packets),
        "insights": find_insights(packets),
        "packets": packets,
    }


def _protocol_counts(packets: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for p in packets:
        counts[p["proto"]] = counts.get(p["proto"], 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


# ---------------------------------------------------------------------- insights


def find_insights(packets: list[dict]) -> list[dict]:
    """Point at the packets that explain what went wrong.

    Each insight is {"severity": "problem" | "info", "kind", "text", "packets", "filter"}.
    Problems come first. "info" entries are true but usually harmless (probe traffic,
    abortive closes), listed so nobody mistakes them for the fault.
    """
    out: list[dict] = []

    def note(kind: str, text: str, nos: list[int], wireshark: str, severity: str = "problem") -> None:
        out.append({"severity": severity, "kind": kind, "text": text, "packets": nos[:12], "filter": wireshark})

    def s(n: int) -> str:
        return "" if n == 1 else "s"

    # ------------------------------------------------------------------ DNS
    queries: dict[tuple, dict] = {}
    for p in packets:
        dns = p.get("dns")
        if not dns:
            continue
        key = (dns["id"], dns["name"], dns["qtype"])
        if not dns["response"]:
            queries.setdefault(key, {"asked": [], "answered": False, "server": p["dst"]})["asked"].append(p["no"])
        else:
            if key in queries:
                queries[key]["answered"] = True
            if dns["rcode"] != "NOERROR":
                note("dns", f"DNS server {p['src']} answers the {dns['qtype']} query for {dns['name']} with {dns['rcode']}.", [p["no"]], f'dns.flags.rcode != 0 && dns.qry.name == "{dns["name"]}"')
    lost: dict[tuple, list[int]] = {}
    for (_txid, name, _qtype), q in queries.items():
        if not q["answered"]:
            lost.setdefault((name, q["server"]), []).extend(q["asked"])
    for (name, server), nos in lost.items():
        note("dns", f"{len(nos)} DNS quer{'ies' if len(nos) != 1 else 'y'} for {name} to {server} never get a response: the client retries, then gives up.", nos, f'dns.qry.name == "{name}" && !dns.response_in')

    # ------------------------------------------------------------------ TCP
    flows: dict[tuple, list[dict]] = {}
    for p in packets:
        if "tcp" in p:
            a, b = (p["src"], p["sport"]), (p["dst"], p["dport"])
            flows.setdefault(tuple(sorted((a, b))), []).append(p)
    benign_resets: list[int] = []
    for flow in flows.values():
        syn = next((p for p in flow if p["tcp"]["flags"] == ["SYN"]), None)
        synack = next((p for p in flow if p["tcp"]["flags"] == ["SYN", "ACK"]), None)
        rst = next((p for p in flow if "rst" in p["tags"]), None)
        if syn and not synack:
            syns = [p["no"] for p in flow if p["tcp"]["flags"] == ["SYN"]]
            if rst:
                note("tcp", f"The SYN to {syn['dst']}:{syn['dport']} is answered with RST: the port is closed (or a firewall rejects it).", [syn["no"], rst["no"]], f"tcp.port == {syn['dport']} && tcp.flags.reset == 1")
            else:
                note("tcp", f"{len(syns)} SYN{s(len(syns))} to {syn['dst']}:{syn['dport']} get no reply at all: the packets are dropped (filtered port or dead host).", syns, f"tcp.port == {syn['dport']} && tcp.flags.syn == 1 && tcp.flags.ack == 0")
            continue
        if rst and synack and synack["no"] < rst["no"]:
            server = synack["src"]
            server_sent = sum(p["tcp"]["len"] for p in flow if p["src"] == server and p["no"] < rst["no"])
            client_data = [p for p in flow if p["src"] != server and p["tcp"]["len"] > 0 and p["no"] < rst["no"]]
            if rst["src"] == server and server_sent == 0:
                if client_data:
                    last = client_data[-1]
                    what = last["info"].split(" (")[0].split(" [")[0] if last["proto"] in ("TLS", "HTTP") else f"{last['tcp']['len']} bytes of data"
                    text = f"The TCP handshake completes and the client sends \"{what}\", but {server} never answers it: it resets the connection instead."
                    nos = [synack["no"], last["no"], rst["no"]]
                else:
                    text = f"{server} accepts the TCP handshake and then resets the connection before any data is exchanged."
                    nos = [synack["no"], rst["no"]]
                note("tcp", text, nos, f"tcp.flags.reset == 1 && ip.src == {server}")
            else:
                benign_resets.append(rst["no"])
        retrans = [p for p in flow if "retransmission" in p["tags"]]
        if len(retrans) >= 2:
            sender = retrans[0]["src"]
            big = max(p["ip"]["len"] for p in retrans)
            gaps = [round(b["time"] - a["time"], 2) for a, b in zip(retrans, retrans[1:]) if b["src"] == a["src"]][:5]
            text = f"{sender} retransmits the same data {len(retrans)} times (IP packets of up to {big} bytes) and it is never acknowledged"
            if len(gaps) >= 2 and gaps[-1] > gaps[0]:
                text += f"; the wait between tries keeps doubling ({', '.join(f'{g} s' for g in gaps)}), which is TCP's exponential backoff"
            note("tcp", text + ".", [p["no"] for p in retrans], "tcp.analysis.retransmission")
        else:
            data = [p for p in flow if p["tcp"]["len"] > 0]
            for a, b in zip(flow, flow[1:]):
                if b["time"] - a["time"] >= 3 and data and data[0]["no"] <= a["no"]:
                    note("tcp", f"The connection {flow[0]['src']}:{flow[0]['sport']} ↔ {flow[0]['dst']}:{flow[0]['dport']} goes silent for {b['time'] - a['time']:.1f} s after packet {a['no']} ({a['info'][:60]}): data was expected and nothing arrives.", [a["no"], b["no"]], f"tcp.port == {flow[0]['sport']} && tcp.time_delta > 3")
                    break

    # ------------------------------------------------------------------ TLS
    legacy = {"TLS 1.0", "TLS 1.1", "SSL 3.0"}
    for p in packets:
        tls = p.get("tls")
        if not (tls and tls["alert"] and tls["alert"]["level"] == "fatal"):
            continue
        desc = tls["alert"]["description"]
        same_flow = [q for q in packets if q["no"] < p["no"] and q.get("tls") and {q.get("sport"), q.get("dport")} == {p.get("sport"), p.get("dport")}]
        hello = next((q for q in reversed(same_flow) if q["tls"]["offered"]), None)
        server_hello = next((q for q in reversed(same_flow) if q["tls"]["selected"]), None)
        f = "tls.alert_message.level == 2"
        if hello and p["src"] == hello["dst"]:  # the server refuses the Client Hello
            offered = sorted(hello["tls"]["offered"])
            if desc == "protocol_version" and set(offered) <= legacy:
                note("tls", f"A Client Hello offering only {', '.join(offered)} is refused with protocol_version: the server correctly rejects that deprecated version.", [hello["no"], p["no"]], f, "info")
            else:
                note("tls", f"The Client Hello offers {' and '.join(offered)}; {p['src']} answers with a fatal alert ({desc}) instead of a Server Hello.", [hello["no"], p["no"]], f)
        elif hello and server_hello and p["src"] == hello["src"]:  # the client refuses the Server Hello
            note("tls", f"The server selects {server_hello['tls']['selected']} in its Server Hello and the client rejects it with a fatal alert ({desc}).", [hello["no"], server_hello["no"], p["no"]], f)
        elif not hello:
            note("tls", f"{p['src']} sends a TLS alert ({desc}) on a connection where no Client Hello was ever sent: a bare port probe that connected and hung up.", [p["no"]], f, "info")
        else:
            note("tls", f"{p['src']} sends a fatal TLS alert: {desc}.", [p["no"]], f)

    # ------------------------------------------------------------------ MTU
    need = [p for p in packets if "frag-needed" in p["tags"]]
    if need:
        note("mtu", f"{need[0]['src']} reports 'fragmentation needed' ({need[0]['info'].split(', ')[-1]}): a packet with Don't-Fragment set was too big for the next link. Path-MTU discovery is working.", [p["no"] for p in need], "icmp.type == 3 && icmp.code == 4", "info")
    frags = [p for p in packets if "fragment" in p["tags"]]
    if frags:
        note("mtu", f"{len(frags)} IP fragments in the capture: packets are being split on the path.", [p["no"] for p in frags], "ip.flags.mf == 1 || ip.frag_offset > 0", "info")

    pings: dict[tuple, dict] = {}
    for p in packets:
        icmp = p.get("icmp")
        if icmp and icmp["type"] in (0, 8) and " seq=" in p["info"]:
            ident = p["info"].split("id=")[1].split(" len=")[0]
            peer = p["dst"] if icmp["type"] == 8 else p["src"]
            entry = pings.setdefault((peer, ident), {"req": None, "reply": False})
            if icmp["type"] == 8:
                entry["req"] = entry["req"] or p
            else:
                entry["reply"] = True
    answered = [e["req"]["ip"]["len"] for e in pings.values() if e["req"] and e["reply"] and e["req"]["ip"]["df"]]
    dropped = [e["req"] for e in pings.values() if e["req"] and not e["reply"] and e["req"]["ip"]["df"]]
    if answered and dropped and min(p["ip"]["len"] for p in dropped) > max(answered) and not need:
        smallest = min(p["ip"]["len"] for p in dropped)
        note("mtu", f"Pings with Don't-Fragment set are answered up to {max(answered)} bytes, but every one of {smallest} bytes or more disappears and no ICMP error comes back: a path-MTU black hole.", [p["no"] for p in dropped], "icmp.type == 8 && ip.flags.df == 1 && !icmp.resp_in")

    # A router captured on the "any" interface shows each forwarded packet twice (in, then out).
    # Packets that come in and never go out were dropped by this router.
    seen_out = {(p["src"], p["dst"], p["ip"]["id"], p["ip"]["len"]) for p in packets if p.get("dir") == "out" and "ip" in p}
    twins = [p for p in packets if p.get("dir") == "in" and "ip" in p and (p["src"], p["dst"], p["ip"]["id"], p["ip"]["len"]) in seen_out]
    if len(twins) >= 5:
        via = {p["dst"] for p in twins}
        # TTL 1 arrivals expire here by design (traceroute probes), so they do not count as drops.
        stuck = [p for p in packets if p.get("dir") == "in" and "ip" in p and p["ip"]["ttl"] > 1 and p["dst"] in via and (p["src"], p["dst"], p["ip"]["id"], p["ip"]["len"]) not in seen_out]
        biggest_ok = max(p["ip"]["len"] for p in twins)
        if stuck and min(p["ip"]["len"] for p in stuck) > biggest_ok:
            df = all(p["ip"]["df"] for p in stuck)
            note("mtu", f"This router forwards packets of up to {biggest_ok} bytes (each is seen coming in and going out), but {len(stuck)} packets of {min(p['ip']['len'] for p in stuck)}-{max(p['ip']['len'] for p in stuck)} bytes come in and never leave"
                 + (", all with Don't-Fragment set" if df else "") + ". It is dropping them, and no ICMP 'fragmentation needed' goes back to the sender.", [p["no"] for p in stuck], f"ip.len > {biggest_ok} && ip.flags.df == 1")

    if benign_resets:
        n = len(benign_resets)
        note("tcp", f"{n} other connection{s(n)} end{'s' if n == 1 else ''} with a RST after the two sides had already talked (or after a scanner's half-open probe). That is an abrupt close, not the fault.", benign_resets, "tcp.flags.reset == 1", "info")

    out.sort(key=lambda i: i["severity"] != "problem")
    return out
