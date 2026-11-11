"""Runs the diagnostic chain and assembles the report."""

from __future__ import annotations

import platform
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import __version__
from .checks.base import Context
from .checks.dns import check_dns
from .checks.http import check_http
from .checks.network import check_mtr, check_mtu, check_ping, check_traceroute
from .checks.ports import check_ports
from .checks.tls import check_tls
from .diagnosis import diagnose
from .models import CheckResult, Report, Status
from .util import have, parse_target

CHECKS: list[tuple[str, str]] = [
    ("dns", "DNS lookup"),
    ("ping", "Ping (ICMP echo)"),
    ("traceroute", "Traceroute"),
    ("mtr", "MTR (per-hop loss and latency)"),
    ("mtu", "Path MTU (DF-bit ping sweep)"),
    ("ports", "TCP port check"),
    ("tls", "TLS handshake and certificate"),
    ("http", "HTTP response"),
]
TOOLS = ("dig", "ping", "traceroute", "mtr", "nmap", "openssl", "curl", "tcpdump")

Event = Callable[[dict], None]


def environment() -> dict:
    return {
        "version": __version__,
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "tools": {t: have(t) for t in TOOLS},
    }


def run_diagnosis(
    raw_target: str,
    *,
    ports: list[int] | None = None,
    resolver: str | None = None,
    dns_port: int = 53,
    timeout: float = 5.0,
    tls_max: str | None = None,
    skip: tuple[str, ...] = (),
    on_event: Event | None = None,
) -> Report:
    """Diagnose one hostname or URL. Raises TargetError for unusable input."""
    target = parse_target(raw_target)
    emit = on_event or (lambda e: None)
    wanted = sorted({target.port, *(ports if ports else (80, 443))})
    ctx = Context(target=target, resolver=resolver, dns_port=dns_port, ports=wanted, timeout=timeout, tls_max=tls_max)
    report = Report(
        id=uuid.uuid4().hex[:12],
        target=target,
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        environment=environment(),
    )
    started = time.monotonic()
    emit({"type": "start", "id": report.id, "target": target.url, "checks": [{"id": i, "title": t} for i, t in CHECKS]})

    def step(check_id: str, fn, skip_reason: str | None = None) -> CheckResult:
        title = dict(CHECKS)[check_id]
        if check_id in skip:
            skip_reason = "Skipped on request."
        if skip_reason:
            res = CheckResult(check_id, title, Status.SKIP, skip_reason)
        else:
            emit({"type": "check_started", "id": check_id})
            t0 = time.monotonic()
            try:
                res = fn(ctx)
            except Exception as exc:  # a broken probe must never take the whole report down
                res = CheckResult(check_id, title, Status.SKIP, f"This check crashed: {type(exc).__name__}: {exc}")
            res.duration_ms = int((time.monotonic() - t0) * 1000)
        ctx.results[check_id] = res
        emit({"type": "check_finished", "check": res.to_dict()})
        return res

    step("dns", check_dns)
    report.resolved_ip = ctx.ip
    no_ip = None if ctx.ip else "Skipped: there is no IP address to test because DNS failed."

    def service_chain() -> None:
        tcp = step("ports", check_ports, no_ip)
        is_open = tcp.details.get("primary", {}).get("state") == "open"
        closed = no_ip or (None if is_open else f"Skipped: TCP {target.port} is not open.")
        tls_skip = closed or (None if target.scheme == "https" else "Skipped: plain HTTP target, no TLS involved.")
        tls = step("tls", check_tls, tls_skip)
        http_skip = closed
        if not http_skip and tls.status == Status.FAIL and not tls.details.get("handshake_ok"):
            http_skip = "Skipped: HTTPS needs a TLS session and the handshake failed."
        step("http", check_http, http_skip)

    with ThreadPoolExecutor(max_workers=5) as pool:
        jobs = [pool.submit(service_chain)]
        for check_id, fn in (("ping", check_ping), ("traceroute", check_traceroute), ("mtr", check_mtr), ("mtu", check_mtu)):
            jobs.append(pool.submit(step, check_id, fn, no_ip))
        for job in jobs:
            job.result()

    report.checks = [ctx.results[i] for i, _ in CHECKS if i in ctx.results]
    report.duration_ms = int((time.monotonic() - started) * 1000)
    diagnose(report)
    emit({"type": "report", "report": report.to_dict()})
    return report
