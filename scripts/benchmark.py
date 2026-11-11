#!/usr/bin/env python3
"""Measure how often NetTriage names the right root cause.

Every case is a target whose fault is known in advance. A case passes when the
tool's top finding is the expected one (or, for a healthy target, when it
reports no critical finding). Nothing here is estimated: the script runs the
real tool and writes what it observed to docs/METRICS.md and docs/metrics.json.

    backend/.venv/bin/python scripts/benchmark.py            # live + lab + captures
    backend/.venv/bin/python scripts/benchmark.py --no-lab   # skip the Docker lab
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from nettriage.engine import run_diagnosis  # noqa: E402
from nettriage.pcap import parse_pcap  # noqa: E402

HEALTHY = None  # expected "finding" for a target with nothing wrong

# (layer, target, expected top finding, what is wrong with it)
LIVE = [
    ("control", "https://github.com", HEALTHY, "healthy site"),
    ("control", "https://www.cloudflare.com", HEALTHY, "healthy site"),
    ("control", "https://1.1.1.1", HEALTHY, "healthy, IP literal"),
    ("dns", "https://nettriage-no-such-name-zz91.com", "DNS_NXDOMAIN", "name does not exist"),
    ("tcp", "http://localhost:9", "TCP_PORT_CLOSED", "nothing listening (RST)"),
    ("tcp", "https://example.com:81", "TCP_PORT_FILTERED", "firewalled port (silence)"),
    ("tls", "https://expired.badssl.com", "TLS_CERT_EXPIRED", "expired certificate"),
    ("tls", "https://wrong.host.badssl.com", "TLS_HOSTNAME_MISMATCH", "certificate for another name"),
    ("tls", "https://self-signed.badssl.com", "TLS_SELF_SIGNED", "self-signed certificate"),
    ("tls", "https://untrusted-root.badssl.com", "TLS_UNTRUSTED_CHAIN", "unknown root CA"),
    ("tls", "https://tls-v1-0.badssl.com:1010", "TLS_VERSION_MISMATCH", "TLS 1.0-only server"),
    ("http", "https://httpbin.org/status/503", "HTTP_5XX", "application returns 503"),
]
LAB = [
    ("control", "https://healthy.lab", "443", HEALTHY, "healthy lab server"),
    ("dns", "https://app.silent.lab", "443", "DNS_TIMEOUT", "resolver never answers"),
    ("dns", "https://ghost.lab", "443", "DNS_NXDOMAIN", "name does not exist"),
    ("tcp", "http://reset.lab:8080/", "8080", "HTTP_RESET", "RST after the request"),
    ("tls", "https://legacy-tls.lab", "443", "TLS_VERSION_MISMATCH", "TLS 1.0-only server"),
    ("network", "http://bigfile.lab/", "80", "MTU_BLACKHOLE", "path-MTU black hole"),
]
# capture file -> insight kinds that must be flagged as faults (empty = must be clean)
CAPTURES = {
    "00-baseline/client.pcap": [],
    "01-dns-failure/client.pcap": ["dns"],
    "01-dns-failure/nxdomain.pcap": ["dns"],
    "02-tcp-reset/client.pcap": ["tcp"],
    "03-tls-version-mismatch/client.pcap": ["tls"],
    "04-mtu-blackhole/client.pcap": ["mtu", "tcp"],
    "04-mtu-blackhole/r2.pcap": ["mtu", "tcp"],
}


def score(report: dict, expected: str | None) -> tuple[bool, str]:
    critical = [f["code"] for f in report["findings"] if f["severity"] == "critical"]
    got = critical[0] if critical else "(healthy)"
    return (not critical if expected is None else got == expected), got


def run_live(case) -> dict:
    layer, target, expected, what = case
    start = time.monotonic()
    try:
        report = run_diagnosis(target).to_dict()
        ok, got = score(report, expected)
    except Exception as exc:  # a crash is a failed case, not a skipped one
        ok, got, report = False, f"crash: {exc}", {"headline": ""}
    return {"where": "internet", "layer": layer, "target": target, "fault": what, "expected": expected or "(healthy)", "got": got, "pass": ok,
            "seconds": round(time.monotonic() - start, 1), "headline": report["headline"]}  # fmt: skip


def run_lab(case) -> dict:
    layer, target, ports, expected, what = case
    start = time.monotonic()
    proc = subprocess.run(
        ["docker", "compose", "exec", "-T", "client", "nettriage", target, "--resolver", "10.77.0.53", "--ports", ports, "--json"],
        cwd=ROOT / "labs", capture_output=True, text=True, timeout=180,
    )  # fmt: skip
    try:
        report = json.loads(proc.stdout)
        ok, got = score(report, expected)
    except json.JSONDecodeError:
        ok, got, report = False, "no report: " + proc.stderr.strip()[-80:], {"headline": ""}
    return {"where": "lab", "layer": layer, "target": target, "fault": what, "expected": expected or "(healthy)", "got": got, "pass": ok,
            "seconds": round(time.monotonic() - start, 1), "headline": report["headline"]}  # fmt: skip


def run_captures() -> dict:
    rows, packets, elapsed = [], 0, 0.0
    for name, kinds in CAPTURES.items():
        path = ROOT / "labs" / "captures" / name
        if not path.is_file():
            continue
        t0 = time.perf_counter()
        for _ in range(20):  # repeat to get a stable decode-speed figure
            result = parse_pcap(path)
        elapsed += time.perf_counter() - t0
        packets += result["packet_count"] * 20
        faults = sorted({i["kind"] for i in result["insights"] if i["severity"] == "problem"})
        ok = (faults == []) if not kinds else all(k in faults for k in kinds)
        rows.append({"capture": name, "packets": result["packet_count"], "expected": kinds or ["none"], "flagged": faults or ["none"], "pass": ok})
    return {"rows": rows, "packets_per_second": int(packets / elapsed) if elapsed else 0}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-lab", action="store_true", help="skip the Docker lab cases")
    ap.add_argument("--rounds", type=int, default=2, help="how many times to run each internet case (default 2)")
    args = ap.parse_args()

    cases: list[dict] = []
    for rnd in range(args.rounds):
        print(f"internet cases, round {rnd + 1} of {args.rounds} ...", flush=True)
        with ThreadPoolExecutor(max_workers=3) as pool:
            for row in pool.map(run_live, LIVE):
                row["round"] = rnd + 1
                cases.append(row)
                print(f"  {'PASS' if row['pass'] else 'FAIL'}  {row['target']:<44} {row['got']}", flush=True)
    if not args.no_lab:
        print("lab cases ...", flush=True)
        subprocess.run(["docker", "compose", "up", "-d", "--wait"], cwd=ROOT / "labs", capture_output=True, check=True)
        for case in LAB:
            row = run_lab(case)
            row["round"] = 1
            cases.append(row)
            print(f"  {'PASS' if row['pass'] else 'FAIL'}  {row['target']:<44} {row['got']}", flush=True)
    captures = run_captures()

    faults = [c for c in cases if c["expected"] != "(healthy)"]
    healthy = [c for c in cases if c["expected"] == "(healthy)"]
    distinct = {(c["where"], c["target"]) for c in cases}
    summary = {
        "date": date.today().isoformat(),
        "runs": len(cases),
        "distinct_targets": len(distinct),
        "distinct_fault_types": len({c["expected"] for c in faults}),
        "root_cause_correct": sum(c["pass"] for c in faults),
        "fault_runs": len(faults),
        "healthy_runs": len(healthy),
        "false_alarms": sum(not c["pass"] for c in healthy),
        "median_seconds": round(statistics.median(c["seconds"] for c in cases), 1),
        "p90_seconds": round(sorted(c["seconds"] for c in cases)[int(len(cases) * 0.9) - 1], 1),
        "captures_total": len(captures["rows"]),
        "captures_correct": sum(r["pass"] for r in captures["rows"]),
        "capture_packets": sum(r["packets"] for r in captures["rows"]),
        "packets_per_second": captures["packets_per_second"],
    }
    (ROOT / "docs" / "metrics.json").write_text(json.dumps({"summary": summary, "cases": cases, "captures": captures["rows"]}, indent=2) + "\n")

    s = summary
    md = [
        "# Measured results",
        "",
        f"Produced by `scripts/benchmark.py` on {s['date']}. Every figure below was observed in that run; re-run the script to reproduce it.",
        "",
        "## Root-cause accuracy",
        "",
        "Each case is a target whose fault is known in advance. A fault case passes only if the tool's top finding is the expected one. A healthy case passes only if the tool raises no critical finding.",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Correct root cause on fault runs | **{s['root_cause_correct']} of {s['fault_runs']}** |",
        f"| False alarms on healthy runs | **{s['false_alarms']} of {s['healthy_runs']}** |",
        f"| Distinct targets | {s['distinct_targets']} ({s['distinct_fault_types']} different fault types across DNS, TCP, TLS, HTTP and path MTU) |",
        f"| Time for a full 8-check diagnosis | median {s['median_seconds']} s, 90th percentile {s['p90_seconds']} s |",
        "",
        "| Where | Layer | Target | Planted or known fault | Expected | Reported | Result | Time |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for c in cases:
        md.append(f"| {c['where']} (run {c['round']}) | {c['layer']} | `{c['target']}` | {c['fault']} | `{c['expected']}` | `{c['got']}` | {'pass' if c['pass'] else '**FAIL**'} | {c['seconds']} s |")
    md += [
        "",
        "## Packet-capture analyser",
        "",
        f"Run over the {s['captures_total']} recorded lab captures ({s['capture_packets']} packets). A capture passes when every expected fault type is flagged, and the baseline capture passes only if nothing is flagged.",
        "",
        "| Measure | Result |",
        "|---|---|",
        f"| Captures analysed correctly | **{s['captures_correct']} of {s['captures_total']}** |",
        f"| Decode speed (pure Python, single thread) | about {s['packets_per_second']:,} packets per second |",
        "",
        "| Capture | Packets | Must flag | Flagged | Result |",
        "|---|---|---|---|---|",
    ]
    for r in captures["rows"]:
        md.append(f"| `{r['capture']}` | {r['packets']} | {', '.join(r['expected'])} | {', '.join(r['flagged'])} | {'pass' if r['pass'] else '**FAIL**'} |")
    md += [
        "",
        "## What these numbers do not show",
        "",
        "- The cases are a small, hand-picked set of textbook faults. Passing them shows the tool recognises those faults, not that it is right on every network.",
        "- The internet cases depend on third-party test hosts (badssl.com, httpbin.org) and can fail when those hosts misbehave.",
        "- Lab captures are small. The decode speed is a relative figure for this machine, not a capacity claim.",
        "",
    ]
    (ROOT / "docs" / "METRICS.md").write_text("\n".join(md))
    print(json.dumps(summary, indent=2))
    return 0 if s["root_cause_correct"] == s["fault_runs"] and not s["false_alarms"] else 1


if __name__ == "__main__":
    sys.exit(main())
