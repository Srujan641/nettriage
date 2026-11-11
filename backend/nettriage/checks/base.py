"""Shared context passed to every check."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import CheckResult, Target


@dataclass
class Context:
    target: Target
    ip: str | None = None  # address every later check connects to
    resolver: str | None = None  # custom DNS server, e.g. a lab resolver
    dns_port: int = 53
    ports: list[int] = field(default_factory=list)
    timeout: float = 5.0  # per-connection timeout, seconds
    tls_max: str | None = None  # cap the client's TLS version ("1.2") to emulate an old client
    results: dict[str, CheckResult] = field(default_factory=dict)

    def result(self, check_id: str) -> CheckResult | None:
        return self.results.get(check_id)
