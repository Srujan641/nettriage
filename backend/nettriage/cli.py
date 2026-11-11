"""Command-line interface.

    nettriage example.com
    nettriage https://example.com:8443/health --ports 22,80,443 -v
    nettriage pcap capture.pcap
    nettriage serve
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .capture import Capture
from .engine import run_diagnosis
from .models import Status
from .pcap import PcapError, parse_pcap
from .render import Painter, check_line, render_markdown, render_terminal
from .util import TargetError

EXIT = {Status.OK: 0, Status.WARN: 1, Status.FAIL: 2}
COMMANDS = ("diagnose", "pcap", "serve")


def _ports(text: str) -> list[int]:
    try:
        ports = [int(p) for p in text.split(",") if p.strip()]
    except ValueError:
        raise argparse.ArgumentTypeError("ports must be comma-separated numbers, e.g. 22,80,443") from None
    if not ports or any(not 0 < p < 65536 for p in ports) or len(ports) > 64:
        raise argparse.ArgumentTypeError("give 1-64 ports between 1 and 65535")
    return ports


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nettriage", description="Layered network diagnostics with a plain-English root-cause report.")
    p.add_argument("--version", action="version", version=f"nettriage {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    d = sub.add_parser("diagnose", help="run the full diagnostic chain against a hostname or URL (default command)")
    d.add_argument("target", help="hostname, host:port, IP address or http(s) URL")
    d.add_argument("--ports", type=_ports, help="TCP ports to check besides the target's own (default: 80,443)")
    d.add_argument("--resolver", help="DNS server to query instead of the system resolver")
    d.add_argument("--dns-port", type=int, default=53, help="port of that DNS server (default 53)")
    d.add_argument("--timeout", type=float, default=5.0, help="per-connection timeout in seconds (default 5)")
    d.add_argument("--tls-max", choices=["1.1", "1.2"], help="cap the client TLS version, to reproduce what an older client sees")
    d.add_argument("--skip", default="", help="comma-separated checks to skip (ping,traceroute,mtr,mtu,tls,http)")
    d.add_argument("--pcap", metavar="FILE", help="record the traffic to FILE with tcpdump while diagnosing (needs root)")
    d.add_argument("--interface", help="capture interface for --pcap (default: any on Linux, en0 on macOS)")
    d.add_argument("--capture-filter", default="", metavar="BPF", help="tcpdump filter for --pcap, e.g. 'not arp'")
    d.add_argument("--json", action="store_true", help="print the full report as JSON")
    d.add_argument("--markdown", action="store_true", help="print the report as Markdown")
    d.add_argument("-o", "--output", metavar="FILE", help="also save the report (.json or .md by extension)")
    d.add_argument("-v", "--verbose", action="store_true", help="show every command that was run and its raw output")
    d.add_argument("--no-color", action="store_true")

    c = sub.add_parser("pcap", help="decode a .pcap/.pcapng file and point out the packets that matter")
    c.add_argument("file")
    c.add_argument("--json", action="store_true")
    c.add_argument("--limit", type=int, default=60, help="packets to list (default 60)")
    c.add_argument("--no-color", action="store_true")

    s = sub.add_parser("serve", help="start the local REST API used by the web dashboard")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8000)
    return p


def cmd_diagnose(args) -> int:
    machine = args.json or args.markdown
    paint = Painter(sys.stdout.isatty() and not args.no_color)
    live = not machine

    def on_event(event: dict) -> None:
        if not live:
            return
        if event["type"] == "start":
            print(paint(f"nettriage {__version__}", "bold") + f"  diagnosing {event['target']}\n")
            print(paint("CHECKS", "bold"))
        elif event["type"] == "check_finished":
            print(check_line(event["check"], paint), flush=True)

    capture = Capture(args.pcap, args.interface, args.capture_filter) if args.pcap else None
    try:
        if capture:
            capture.__enter__()
            if capture.error:
                print(f"warning: packet capture not started: {capture.error}", file=sys.stderr)
        report = run_diagnosis(
            args.target,
            ports=args.ports,
            resolver=args.resolver,
            dns_port=args.dns_port,
            timeout=args.timeout,
            tls_max=args.tls_max,
            skip=tuple(s.strip() for s in args.skip.split(",") if s.strip()),
            on_event=on_event,
        )
    except TargetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 64
    finally:
        if capture:
            capture.__exit__(None, None, None)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    elif args.markdown:
        print(render_markdown(report))
    else:
        print()
        print(render_terminal(report, paint, verbose=args.verbose, checks=False))
        if capture and not capture.error:
            print(paint(f"Capture saved to {args.pcap}  (open in Wireshark, or: nettriage pcap {args.pcap})", "dim"))

    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(report) if path.suffix == ".md" else json.dumps(report.to_dict(), indent=2))
    return EXIT[report.overall]


def cmd_pcap(args) -> int:
    try:
        result = parse_pcap(args.file)
    except (OSError, PcapError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 66
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    paint = Painter(sys.stdout.isatty() and not args.no_color)
    protos = ", ".join(f"{k} {v}" for k, v in result["protocols"].items())
    print(paint(result["file"], "bold") + f"  {result['packet_count']} packets over {result['duration_s']:.2f} s  ({protos})\n")
    print(paint("WHAT THE CAPTURE SHOWS", "bold"))
    for i in result["insights"] or [{"text": "Nothing abnormal detected.", "packets": [], "filter": ""}]:
        nos = f"  [packets {', '.join(map(str, i['packets']))}]" if i["packets"] else ""
        mark = paint("✖", "fail") if i.get("severity", "problem") == "problem" and i["packets"] else paint("·", "dim")
        print(f"  {mark} {i['text']}{paint(nos, 'dim')}")
        if i["filter"]:
            print(paint(f"    Wireshark filter: {i['filter']}", "cyan"))
    print("\n" + paint(f"{'No.':>4} {'Time':>9}  {'Source':<15} {'Destination':<15} {'Proto':<5} {'Len':>5}  Info", "bold"))
    for p in result["packets"][: args.limit]:
        style = ("fail",) if {"rst", "tls-alert", "dns-error", "frag-needed"} & set(p["tags"]) else ("warn",) if p["tags"] else ()
        print(paint(f"{p['no']:>4} {p['time']:>9.4f}  {p['src']:<15} {p['dst']:<15} {p['proto']:<5} {p['length']:>5}  {p['info']}", *style))
    if result["packet_count"] > args.limit:
        print(paint(f"... {result['packet_count'] - args.limit} more (use --limit)", "dim"))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in COMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "diagnose")  # `nettriage example.com` is shorthand for `nettriage diagnose example.com`
    args = build_parser().parse_args(argv)
    if args.command == "pcap":
        return cmd_pcap(args)
    if args.command == "serve":
        from .api import serve

        return serve(args.host, args.port)
    return cmd_diagnose(args)


if __name__ == "__main__":
    sys.exit(main())
