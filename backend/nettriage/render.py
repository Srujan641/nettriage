"""Terminal and Markdown renderers for a report."""

from __future__ import annotations

import textwrap

from .models import CheckResult, Report, Status

_COLORS = {"ok": "32", "warn": "33", "fail": "31", "skip": "90", "bold": "1", "dim": "2", "cyan": "36"}
_ICONS = {Status.OK: ("✔", "ok"), Status.WARN: ("▲", "warn"), Status.FAIL: ("✖", "fail"), Status.SKIP: ("–", "skip")}
_SEVERITY = {"critical": ("fail", "CRITICAL"), "warning": ("warn", "WARNING"), "info": ("cyan", "INFO")}
_VERDICT = {Status.OK: "HEALTHY", Status.WARN: "DEGRADED", Status.FAIL: "BROKEN"}


class Painter:
    def __init__(self, color: bool):
        self.color = color

    def __call__(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        return f"\033[{';'.join(_COLORS[s] for s in styles)}m{text}\033[0m"


def check_line(check: CheckResult | dict, paint: Painter, width: int = 100) -> str:
    if isinstance(check, dict):
        status, title, summary, ms = Status(check["status"]), check["title"], check["summary"], check["duration_ms"]
    else:
        status, title, summary, ms = check.status, check.title, check.summary, check.duration_ms
    icon, style = _ICONS[status]
    head = f"  {paint(icon, style)} {paint(f'{title:<31}', 'bold')} {paint(f'{ms:>6} ms', 'dim')}"
    body = textwrap.fill(summary, width=width - 6, initial_indent="      ", subsequent_indent="      ")
    return f"{head}\n{body}"


def render_terminal(report: Report, paint: Painter, verbose: bool = False, checks: bool = True) -> str:
    out: list[str] = []
    if checks:
        out.append(paint("CHECKS", "bold"))
        out += [check_line(c, paint) for c in report.checks]
        out.append("")

    style = _ICONS[report.overall][1]
    out.append(paint(f"VERDICT: {_VERDICT[report.overall]}", "bold", style))
    out.append(textwrap.fill(report.headline, width=100, initial_indent="  ", subsequent_indent="  "))

    if report.findings:
        out += ["", paint("FINDINGS", "bold")]
        for f in report.findings:
            color, label = _SEVERITY[f.severity]
            out.append(f"  {paint(f'[{label}]', color)} {paint(f.code, 'bold')} {paint('(' + f.layer + ')', 'dim')}")
            out.append(textwrap.fill(f.message, width=100, initial_indent="      ", subsequent_indent="      "))
            if f.evidence:
                out.append(textwrap.fill(f"Evidence: {f.evidence}", width=100, initial_indent="      ", subsequent_indent="      "))
            if f.remedy:
                out.append(textwrap.fill(f"Next step: {f.remedy}", width=100, initial_indent="      ", subsequent_indent="      "))

    if verbose:
        out += ["", paint("EVIDENCE (commands run)", "bold")]
        for c in report.checks:
            for cmd in c.commands:
                out.append(paint(f"  $ {cmd.command}", "cyan"))
                out.append(textwrap.indent(cmd.output.rstrip() or "(no output)", "    "))
    out.append("")
    out.append(paint(f"Report {report.id} · {report.target.url} → {report.resolved_ip or 'unresolved'} · {report.duration_ms / 1000:.1f} s", "dim"))
    return "\n".join(out)


def render_markdown(report: Report) -> str:
    icon = {Status.OK: "✅", Status.WARN: "⚠️", Status.FAIL: "❌", Status.SKIP: "➖"}
    md = [
        f"# Network diagnostic report: {report.target.host}",
        "",
        f"- **Target:** `{report.target.url}`",
        f"- **Resolved address:** `{report.resolved_ip or 'unresolved'}`",
        f"- **Run at:** {report.started_at} (took {report.duration_ms / 1000:.1f} s)",
        f"- **Verdict:** {icon[report.overall]} {_VERDICT[report.overall]}",
        "",
        "## Summary",
        "",
        report.headline,
        "",
    ]
    if report.findings:
        md += ["## Findings", ""]
        for f in report.findings:
            md.append(f"### {f.severity.upper()}: `{f.code}` ({f.layer})")
            md += ["", f.message, ""]
            if f.evidence:
                md += [f"- **Evidence:** {f.evidence}"]
            if f.remedy:
                md += [f"- **Next step:** {f.remedy}"]
            md.append("")
    md += ["## Checks", "", "| | Check | Result | Time |", "|---|---|---|---|"]
    for c in report.checks:
        md.append(f"| {icon[c.status]} | {c.title} | {c.summary.replace('|', '/')} | {c.duration_ms} ms |")
    md += ["", "## Evidence", ""]
    for c in report.checks:
        for cmd in c.commands:
            md += [f"**{c.title}**", "", "```", f"$ {cmd.command}", cmd.output.rstrip() or "(no output)", "```", ""]
    return "\n".join(md)
