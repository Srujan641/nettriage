"""Record the diagnostic's own traffic with tcpdump so it can be opened in Wireshark."""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

from .util import have


class Capture:
    """Context manager around `tcpdump -w`. Capturing needs root (or BPF access on macOS)."""

    def __init__(self, path: str, interface: str | None = None, bpf: str = ""):
        self.path = Path(path)
        self.interface = interface or ("any" if sys.platform.startswith("linux") else "en0")
        self.bpf = bpf
        self.proc: subprocess.Popen | None = None
        self.error: str | None = None

    def __enter__(self) -> Capture:
        if not have("tcpdump"):
            self.error = "tcpdump is not installed"
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        argv = ["tcpdump", "-i", self.interface, "-U", "-n", "-s", "0", "-w", str(self.path)]
        if self.bpf:
            argv.append(self.bpf)
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        time.sleep(1.0)  # let tcpdump attach before the first packet leaves
        if self.proc.poll() is not None:
            self.error = (self.proc.stderr.read() or "tcpdump exited").strip().splitlines()[-1]
            self.proc = None
        return self

    def __exit__(self, *exc) -> None:
        if self.proc is None:
            return
        time.sleep(1.0)  # catch trailing packets (FIN/RST, late retransmissions)
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
