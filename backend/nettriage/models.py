"""Data model shared by every check, the diagnosis engine, the CLI and the API."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    OK = "ok"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass
class CommandRecord:
    """One external command (or built-in probe) that was run, kept as evidence."""

    command: str
    exit_code: int | None = None
    output: str = ""
    duration_ms: int = 0
    timed_out: bool = False


@dataclass
class Finding:
    """One thing the engine concluded, with the evidence and what to do about it."""

    severity: str  # "critical" | "warning" | "info"
    code: str  # stable machine id, e.g. TLS_CERT_EXPIRED
    layer: str  # dns | network | tcp | tls | http
    message: str  # plain English
    evidence: str = ""
    remedy: str = ""


@dataclass
class CheckResult:
    id: str
    title: str
    status: Status = Status.SKIP
    summary: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    commands: list[CommandRecord] = field(default_factory=list)
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class Target:
    raw: str
    host: str
    scheme: str  # "https" | "http"
    port: int
    path: str = "/"
    is_ip: bool = False

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"


@dataclass
class Report:
    id: str
    target: Target
    started_at: str
    duration_ms: int = 0
    resolved_ip: str | None = None
    overall: Status = Status.OK
    headline: str = ""
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    environment: dict[str, Any] = field(default_factory=dict)

    def check(self, check_id: str) -> CheckResult | None:
        return next((c for c in self.checks if c.id == check_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": {**asdict(self.target), "url": self.target.url},
            "started_at": self.started_at,
            "duration_ms": self.duration_ms,
            "resolved_ip": self.resolved_ip,
            "overall": self.overall.value,
            "headline": self.headline,
            "findings": [asdict(f) for f in self.findings],
            "checks": [c.to_dict() for c in self.checks],
            "environment": self.environment,
        }
