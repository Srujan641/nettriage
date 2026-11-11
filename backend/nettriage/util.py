"""Target parsing and safe subprocess execution."""

from __future__ import annotations

import ipaddress
import re
import shlex
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit

from .models import CommandRecord, Target

IS_MAC = sys.platform == "darwin"

_HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)(\.[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?)*\.?$")
MAX_OUTPUT = 20_000


class TargetError(ValueError):
    pass


def parse_target(raw: str) -> Target:
    """Accept `example.com`, `example.com:8443`, `10.0.0.1`, or a full http(s) URL.

    Hostnames are validated strictly: they end up in argv of external tools, so
    anything that could be read as an option (leading '-') or is not a legal
    hostname is rejected here, once, for every caller.
    """
    text = (raw or "").strip()
    if not text:
        raise TargetError("Enter a hostname or URL.")
    if re.search(r"[\s\x00-\x1f\\]", text):
        raise TargetError("A target cannot contain spaces or control characters.")
    if "://" not in text:
        guess = "http" if re.search(r":(80|8080|8000)(/|$)", text) else "https"
        text = f"{guess}://{text}"
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError as exc:
        raise TargetError(f"Could not parse '{raw}': {exc}") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise TargetError(f"Unsupported scheme '{scheme}'. Use http or https.")
    host = (parts.hostname or "").lower()
    if not host:
        raise TargetError(f"No hostname found in '{raw}'.")

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise TargetError(f"'{host}' is not a valid hostname.") from None
        if not _HOST_RE.match(host):
            raise TargetError(f"'{host}' is not a valid hostname.")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(
        raw=raw.strip(),
        host=host.rstrip(".") if not is_ip else host,
        scheme=scheme,
        port=port or (443 if scheme == "https" else 80),
        path=path,
        is_ip=is_ip,
    )


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(argv: list[str], timeout: float = 10.0, stdin: str | None = "") -> CommandRecord:
    """Run a command without a shell and return its combined output as evidence."""
    shown = " ".join(shlex.quote(a) for a in argv)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        out = proc.stdout
        if proc.stderr.strip():
            out = (out.rstrip() + "\n" + proc.stderr) if out.strip() else proc.stderr
        rec = CommandRecord(shown, proc.returncode, out)
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or b""
        if isinstance(partial, bytes):
            partial = partial.decode(errors="replace")
        err = exc.stderr or b""
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        rec = CommandRecord(shown, None, (partial + err).strip(), timed_out=True)
    except FileNotFoundError:
        rec = CommandRecord(shown, 127, f"{argv[0]}: command not found")
    rec.duration_ms = int((time.monotonic() - start) * 1000)
    if len(rec.output) > MAX_OUTPUT:
        rec.output = rec.output[:MAX_OUTPUT] + "\n... [output truncated]"
    return rec


def plural(n: float, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"
