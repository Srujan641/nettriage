"""Layer-3 checks: ping, traceroute, MTR-style per-hop statistics and path-MTU discovery."""

from __future__ import annotations

import os
import re
import select
import socket
import struct
import time
from collections import Counter

from ..models import CheckResult, CommandRecord, Status
from ..util import IS_MAC, have, run
from .base import Context

# --------------------------------------------------------------------------- ping


def _ping_argv(ip: str, count: int = 1, size: int | None = None, df: bool = False, wait_s: float = 1.0):
    argv = ["ping", "-n", "-c", str(count)]
    if count > 1:
        argv += ["-i", "0.3"]
    argv += ["-W", str(int(wait_s * 1000)) if IS_MAC else str(max(1, int(wait_s)))]
    if size is not None:
        argv += ["-s", str(size)]
    if df:
        argv += ["-D"] if IS_MAC else ["-M", "do"]
    return argv + [ip]


def _parse_ping(out: str) -> dict:
    d = {"sent": 0, "received": 0, "loss_pct": 100.0, "rtt": None}
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss", out)
    if m:
        d.update(sent=int(m.group(1)), received=int(m.group(2)), loss_pct=float(m.group(3)))
    m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms", out)
    if m:
        d["rtt"] = dict(zip(("min", "avg", "max", "jitter"), (float(x) for x in m.groups())))
    return d


def check_ping(ctx: Context) -> CheckResult:
    res = CheckResult("ping", "Ping (ICMP echo)")
    rec = run(_ping_argv(ctx.ip, count=5, wait_s=1.5), timeout=15)
    res.commands.append(rec)
    d = _parse_ping(rec.output)
    res.details = d
    if d["received"] == 0:
        res.status = Status.WARN
        res.summary = f"{ctx.ip} did not answer any of {d['sent'] or 5} pings."
    elif d["loss_pct"] > 0:
        res.status = Status.WARN
        res.summary = f"{d['loss_pct']:.0f}% packet loss ({d['received']}/{d['sent']} replies), avg {d['rtt']['avg']:.1f} ms."
    else:
        rtt = d["rtt"] or {"avg": 0, "jitter": 0}
        res.status = Status.OK
        res.summary = f"{d['received']}/{d['sent']} replies, avg {rtt['avg']:.1f} ms, jitter {rtt['jitter']:.1f} ms."
        if rtt["avg"] > 300:
            res.status = Status.WARN
            res.summary += " Latency is high."
    return res


# --------------------------------------------------------------------- traceroute


def check_traceroute(ctx: Context) -> CheckResult:
    res = CheckResult("traceroute", "Traceroute")
    if not have("traceroute"):
        res.summary = "traceroute is not installed."
        return res
    base = ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "20"]
    rec = run(base + ["-I", ctx.ip], timeout=30)  # ICMP probes get through more firewalls
    if rec.exit_code not in (0, None) and not re.search(r"^\s*1\s", rec.output, re.MULTILINE):
        res.commands.append(rec)
        rec = run(base + [ctx.ip], timeout=30)  # fall back to UDP probes
    res.commands.append(rec)

    hops = []
    for line in rec.output.splitlines():
        m = re.match(r"\s*(\d+)\s+(\S+)(?:\s+([\d.]+)\s+ms)?", line)
        if not m:
            continue
        ip = None if m.group(2) == "*" else m.group(2)
        hops.append({"ttl": int(m.group(1)), "ip": ip, "rtt_ms": float(m.group(3)) if m.group(3) else None})
    reached = any(h["ip"] == ctx.ip for h in hops)
    answered = [h for h in hops if h["ip"]]
    res.details = {"hops": hops, "reached": reached, "last_responding": answered[-1] if answered else None}

    if reached:
        res.status = Status.OK
        n = next(h["ttl"] for h in hops if h["ip"] == ctx.ip)
        res.summary = f"Reached {ctx.ip} in {n} hop{'s' if n != 1 else ''}."
    elif answered:
        last = answered[-1]
        res.status = Status.WARN
        res.summary = f"The trace stops answering after hop {last['ttl']} ({last['ip']}); the destination never replied."
    else:
        res.status = Status.WARN
        res.summary = "No hop answered the trace."
    return res


# ---------------------------------------------------------------------------- mtr


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _icmp_socket() -> socket.socket | None:
    for kind in (socket.SOCK_RAW, socket.SOCK_DGRAM):
        try:
            return socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except OSError:
            continue
    return None


def builtin_mtr(ip: str, cycles: int = 5, max_ttl: int = 30) -> list[dict] | None:
    """mtr-equivalent: every cycle sends one ICMP echo per TTL and times the reply.

    Needs no root on macOS (datagram ICMP sockets); uses a raw socket when root.
    Returns None if the OS will not hand out an ICMP socket.
    """
    sock = _icmp_socket()
    if sock is None:
        return None
    ident = os.getpid() & 0xFFFF
    stats: dict[int, dict] = {}
    limit = max_ttl
    try:
        for cycle in range(cycles):
            sent_at: dict[int, tuple[int, float]] = {}
            for ttl in range(1, limit + 1):
                seq = 0x4000 + cycle * 64 + ttl  # offset keeps clear of a concurrent ping's low sequence numbers
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                payload = b"nettriage-probe!"
                head = struct.pack("!BBHHH", 8, 0, 0, ident, seq)
                packet = struct.pack("!BBHHH", 8, 0, _checksum(head + payload), ident, seq) + payload
                try:
                    sock.sendto(packet, (ip, 0))
                except OSError:
                    continue
                sent_at[seq] = (ttl, time.monotonic())
                stats.setdefault(ttl, {"ttl": ttl, "sent": 0, "rtts": [], "ips": Counter()})["sent"] += 1

            deadline = time.monotonic() + 1.0
            pending = set(sent_at)
            reached_ttl = None
            while pending and (left := deadline - time.monotonic()) > 0:
                if not select.select([sock], [], [], left)[0]:
                    break
                data, addr = sock.recvfrom(2048)
                now = time.monotonic()
                if data and data[0] >> 4 == 4:  # strip the IPv4 header if present
                    data = data[(data[0] & 0x0F) * 4 :]
                if len(data) < 8:
                    continue
                kind = data[0]
                if kind == 0 and addr[0] == ip:
                    seq = struct.unpack("!H", data[6:8])[0]
                elif kind in (3, 11) and len(data) >= 36:
                    inner = data[8:]
                    inner = inner[(inner[0] & 0x0F) * 4 :]
                    if len(inner) < 8 or inner[0] != 8:
                        continue
                    seq = struct.unpack("!H", inner[6:8])[0]
                else:
                    continue
                if seq not in pending:
                    continue
                pending.discard(seq)
                ttl, t0 = sent_at[seq]
                stats[ttl]["rtts"].append((now - t0) * 1000)
                stats[ttl]["ips"][addr[0]] += 1
                if kind == 0:
                    reached_ttl = ttl if reached_ttl is None else min(reached_ttl, ttl)
            if reached_ttl:
                limit = min(limit, reached_ttl)
            elif cycle == 0:
                answered = [t for t, s in stats.items() if s["rtts"]]
                limit = min(max_ttl, (max(answered) if answered else 0) + 3)
    finally:
        sock.close()

    hops = []
    for ttl in range(1, limit + 1):
        s = stats.get(ttl)
        if not s:
            continue
        rtts = s["rtts"]
        hops.append(
            {
                "ttl": ttl,
                "ip": s["ips"].most_common(1)[0][0] if s["ips"] else None,
                "sent": s["sent"],
                "loss_pct": round(100 * (1 - len(rtts) / s["sent"]), 1) if s["sent"] else 100.0,
                "best_ms": round(min(rtts), 2) if rtts else None,
                "avg_ms": round(sum(rtts) / len(rtts), 2) if rtts else None,
                "worst_ms": round(max(rtts), 2) if rtts else None,
            }
        )
    return hops


def _parse_mtr_report(out: str) -> list[dict]:
    hops = []
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\.\|--\s+(\S+)\s+([\d.]+)%\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", line)
        if m:
            ip = None if m.group(2) == "???" else m.group(2)
            hops.append(
                {
                    "ttl": int(m.group(1)),
                    "ip": ip,
                    "sent": int(m.group(4)),
                    "loss_pct": float(m.group(3)),
                    "avg_ms": float(m.group(6)) if ip else None,
                    "best_ms": float(m.group(7)) if ip else None,
                    "worst_ms": float(m.group(8)) if ip else None,
                }
            )
    return hops


def _mtr_table(hops: list[dict]) -> str:
    rows = [f"{'HOP':>3}  {'HOST':<16} {'LOSS%':>6} {'SNT':>3} {'BEST':>7} {'AVG':>7} {'WORST':>7}"]
    for h in hops:
        f = lambda v: f"{v:7.1f}" if v is not None else "      -"
        rows.append(
            f"{h['ttl']:>3}  {h['ip'] or '???':<16} {h['loss_pct']:>5.0f}% {h['sent']:>3} "
            f"{f(h['best_ms'])} {f(h['avg_ms'])} {f(h['worst_ms'])}"
        )
    return "\n".join(rows)


def check_mtr(ctx: Context) -> CheckResult:
    res = CheckResult("mtr", "MTR (per-hop loss and latency)")
    hops: list[dict] | None = None
    engine = None
    if have("mtr"):
        rec = run(["mtr", "--report", "--report-cycles", "5", "--no-dns", ctx.ip], timeout=40)
        res.commands.append(rec)
        hops = _parse_mtr_report(rec.output) or None
        engine = "mtr" if hops else None
    if hops is None:
        start = time.monotonic()
        hops = builtin_mtr(ctx.ip)
        if hops is None:
            res.summary = "mtr is not installed and this OS user cannot open an ICMP socket."
            return res
        engine = "built-in"
        res.commands.append(
            CommandRecord(
                f"built-in ICMP path probe (mtr equivalent): 5 cycles, TTL 1-30, target {ctx.ip}",
                0,
                _mtr_table(hops),
                int((time.monotonic() - start) * 1000),
            )
        )

    final = hops[-1] if hops else None
    reached = bool(final and final["ip"] == ctx.ip)
    # Classic MTR reading: loss only counts if it carries through to the last hop.
    lossy_mid = [h for h in hops[:-1] if h["ip"] and h["loss_pct"] >= 20]
    end_loss = final["loss_pct"] if reached else None
    onset = None
    if reached and end_loss and end_loss >= 20:
        for i, h in enumerate(hops):
            if all(x["loss_pct"] >= 20 for x in hops[i:]):
                onset = h
                break
    res.details = {
        "engine": engine,
        "hops": hops,
        "reached": reached,
        "end_to_end_loss_pct": end_loss,
        "loss_onset": onset,
        "rate_limited_hops": [h["ttl"] for h in lossy_mid] if reached and not (end_loss or 0) >= 20 else [],
    }

    if not hops or not any(h["ip"] for h in hops):
        res.status = Status.WARN
        res.summary = "No hop on the path answered ICMP probes."
    elif not reached:
        last = [h for h in hops if h["ip"]][-1]
        res.status = Status.WARN
        res.summary = f"Probes get as far as hop {last['ttl']} ({last['ip']}) and nothing answers beyond it."
    elif onset:
        res.status = Status.WARN
        res.summary = (
            f"{end_loss:.0f}% loss end to end. Loss begins at hop {onset['ttl']} ({onset['ip'] or 'unknown'}) "
            "and continues to the destination, so that hop or its link is dropping traffic."
        )
    else:
        res.status = Status.OK
        res.summary = f"{len(hops)} hop{'s' if len(hops) != 1 else ''}, {end_loss:.0f}% loss at the destination, avg {final['avg_ms']:.1f} ms."
        if res.details["rate_limited_hops"]:
            res.summary += (
                f" Loss seen at hop {', '.join(map(str, res.details['rate_limited_hops']))} does not carry on "
                "to later hops: that is a router rate-limiting its ICMP replies, not real packet loss."
            )
    return res


# ----------------------------------------------------------------------- path MTU


def check_mtu(ctx: Context) -> CheckResult:
    """Find the largest packet that crosses the path with Don't-Fragment set."""
    res = CheckResult("mtu", "Path MTU (DF-bit ping sweep)")

    def probe(size: int) -> tuple[bool, str]:
        rec = run(_ping_argv(ctx.ip, count=1, size=size, df=True, wait_s=1.0), timeout=4)
        res.commands.append(rec)
        ok = _parse_ping(rec.output)["received"] > 0
        signal = "ok" if ok else "silent"
        if not ok and re.search(r"message too long|frag(mentation)? needed|mtu[ =]", rec.output, re.IGNORECASE):
            signal = "icmp"
        return ok, signal

    ok_small, _ = probe(56)
    if not ok_small:
        res.status = Status.SKIP
        res.summary = "Host does not answer ping, so the path MTU cannot be measured with ICMP."
        res.details = {"measurable": False}
        return res

    ok_full, signal = probe(1472)
    if ok_full:
        res.status = Status.OK
        res.summary = "A full 1500-byte packet crosses the path unfragmented."
        res.details = {"measurable": True, "path_mtu": 1500, "blackhole": False}
        return res

    lo, hi = 56, 1472  # lo passes, hi fails
    signals = {signal}
    while hi - lo > 1:
        mid = (lo + hi) // 2
        ok, sig = probe(mid)
        if ok:
            lo = mid
        else:
            hi = mid
            signals.add(sig)
    path_mtu = lo + 28  # ICMP payload + 8 ICMP header + 20 IP header
    blackhole = "icmp" not in signals
    res.details = {"measurable": True, "path_mtu": path_mtu, "blackhole": blackhole, "largest_payload": lo}
    res.status = Status.WARN if blackhole else Status.OK
    if blackhole:
        res.summary = (
            f"Packets up to {path_mtu} bytes get through, but anything larger with Don't-Fragment set vanishes "
            "without an ICMP 'fragmentation needed' reply. That is the signature of a path-MTU black hole."
        )
    else:
        res.summary = (
            f"Path MTU is {path_mtu} bytes (below the usual 1500). Routers do report it with ICMP "
            "'fragmentation needed', so path-MTU discovery can adapt."
        )
    return res
