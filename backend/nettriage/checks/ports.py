"""TCP reachability: a connect() scan that tells open / closed (RST) / filtered (silence) apart."""

from __future__ import annotations

import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from ..models import CheckResult, CommandRecord, Status
from ..util import have, run
from .base import Context

SERVICE_NAMES = {22: "ssh", 25: "smtp", 53: "dns", 80: "http", 443: "https", 3306: "mysql", 5432: "postgres", 8080: "http-alt", 8443: "https-alt"}


def probe_port(ip: str, port: int, timeout: float) -> dict:
    start = time.monotonic()
    state, note = "filtered", "no reply to SYN before the timeout"
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            state, note = "open", "SYN -> SYN/ACK, handshake completed"
    except ConnectionRefusedError:
        state, note = "closed", "SYN answered with RST (connection refused)"
    except TimeoutError:
        pass
    except OSError as exc:
        if exc.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
            state, note = "unreachable", f"no route: {exc.strerror}"
        else:
            note = exc.strerror or str(exc)
    return {
        "port": port,
        "service": SERVICE_NAMES.get(port, ""),
        "state": state,
        "note": note,
        "connect_ms": round((time.monotonic() - start) * 1000, 1),
    }


def check_ports(ctx: Context) -> CheckResult:
    res = CheckResult("ports", "TCP port check")
    ports = ctx.ports
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=min(16, len(ports))) as pool:
        probes = list(pool.map(lambda p: probe_port(ctx.ip, p, ctx.timeout), ports))
    table = "\n".join(f"{p['port']:>5}/tcp  {p['state']:<11} {p['connect_ms']:>7.1f} ms  {p['note']}" for p in probes)
    res.commands.append(
        CommandRecord(f"TCP connect() probe {ctx.ip} ports {','.join(map(str, ports))}", 0, table, int((time.monotonic() - start) * 1000))
    )
    if have("nmap"):
        res.commands.append(
            run(["nmap", "-Pn", "-n", "--host-timeout", "20s", "-p", ",".join(map(str, ports)), ctx.ip], timeout=25)
        )

    primary = next(p for p in probes if p["port"] == ctx.target.port)
    res.details = {"ports": probes, "primary": primary}
    others = ", ".join(f"{p['port']} {p['state']}" for p in probes if p is not primary)
    tail = f" Also checked: {others}." if others else ""
    if primary["state"] == "open":
        res.status = Status.OK
        res.summary = f"TCP {primary['port']} is open (handshake in {primary['connect_ms']:.0f} ms).{tail}"
    elif primary["state"] == "closed":
        res.status = Status.FAIL
        res.summary = f"TCP {primary['port']} is closed: the host answered the SYN with a reset.{tail}"
    else:
        res.status = Status.FAIL
        res.summary = f"TCP {primary['port']} got no answer ({primary['note']}).{tail}"
    return res
