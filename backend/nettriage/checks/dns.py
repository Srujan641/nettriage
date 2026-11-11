"""DNS resolution via dig (falls back to the system resolver API)."""

from __future__ import annotations

import re
import socket

from ..models import CheckResult, Status
from ..util import have, run
from .base import Context

PUBLIC_RESOLVERS = ("1.1.1.1", "8.8.8.8")


def _dig(name: str, rtype: str, resolver: str | None, port: int = 53):
    argv = ["dig", "+time=3", "+tries=2", "+noall", "+comments", "+answer", "+stats"]
    if resolver:
        argv.append(f"@{resolver}")
    if port != 53:
        argv += ["-p", str(port)]
    argv += [name, rtype]
    rec = run(argv, timeout=10)
    out = rec.output
    parsed = {"status": None, "records": [], "cname": [], "ttl": None, "query_ms": None, "server": None}

    m = re.search(r"status: ([A-Z]+)", out)
    if m:
        parsed["status"] = m.group(1)
    elif rec.timed_out or re.search(r"timed out|no servers could be reached", out):
        parsed["status"] = "TIMEOUT"
    elif "connection refused" in out.lower():
        parsed["status"] = "UNREACHABLE"
    else:
        parsed["status"] = "ERROR"

    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 5 and not line.startswith(";") and cols[2] == "IN":
            if cols[3] == rtype:
                parsed["records"].append(cols[4])
                parsed["ttl"] = int(cols[1])
            elif cols[3] == "CNAME":
                parsed["cname"].append(cols[4].rstrip("."))
    m = re.search(r"Query time: (\d+) msec", out)
    if m:
        parsed["query_ms"] = int(m.group(1))
    m = re.search(r"SERVER: ([^\s#]+)#(\d+)", out)
    if m:
        parsed["server"] = m.group(1)
    return rec, parsed


def check_dns(ctx: Context) -> CheckResult:
    res = CheckResult("dns", "DNS lookup")
    host = ctx.target.host

    if ctx.target.is_ip:
        ctx.ip = host
        res.status = Status.OK
        res.summary = f"{host} is already an IP address, so no DNS lookup is needed."
        res.details = {"skipped_reason": "ip_literal", "a": [host], "aaaa": []}
        if have("dig"):
            rec = run(["dig", "+short", "+time=2", "+tries=1", "-x", host], timeout=5)
            res.commands.append(rec)
            ptr = rec.output.strip().splitlines()
            if rec.exit_code == 0 and ptr and not ptr[0].startswith(";"):
                res.details["ptr"] = ptr[0].rstrip(".")
                res.summary += f" Reverse DNS names it {res.details['ptr']}."
        return res

    if not have("dig"):
        return _system_fallback(ctx, res)

    rec_a, a = _dig(host, "A", ctx.resolver, ctx.dns_port)
    rec_aaaa, aaaa = _dig(host, "AAAA", ctx.resolver, ctx.dns_port)
    res.commands += [rec_a, rec_aaaa]
    resolver = ctx.resolver or a["server"] or "the system resolver"
    who = resolver if resolver.startswith("the ") else f"DNS server {resolver}"
    res.details = {
        "resolver": resolver,
        "status": a["status"],
        "a": a["records"],
        "aaaa": aaaa["records"],
        "cname": a["cname"],
        "ttl": a["ttl"],
        "query_ms": a["query_ms"],
        "error_kind": None,
    }

    if a["records"]:
        ctx.ip = a["records"][0]
        res.status = Status.OK
        extra = f" (+{len(a['records']) - 1} more)" if len(a["records"]) > 1 else ""
        via = f" via CNAME {a['cname'][-1]}" if a["cname"] else ""
        res.summary = f"{host} resolves to {ctx.ip}{extra}{via} in {a['query_ms']} ms using {resolver}."
        if a["query_ms"] is not None and a["query_ms"] > 500:
            res.status = Status.WARN
            res.details["error_kind"] = "slow"
            res.summary += " That lookup is slow."
        return res

    # No IPv4 answer: classify the failure.
    kind = {
        "NXDOMAIN": "nxdomain",
        "SERVFAIL": "servfail",
        "REFUSED": "refused",
        "TIMEOUT": "timeout",
        "UNREACHABLE": "unreachable",
        "NOERROR": "nodata",
    }.get(a["status"], "error")
    res.details["error_kind"] = kind
    res.status = Status.FAIL
    res.summary = {
        "nxdomain": f"{host} does not exist: {who} answers NXDOMAIN.",
        "servfail": f"{who} could not complete the lookup for {host} (SERVFAIL).",
        "refused": f"{who} refused to answer the query for {host} (REFUSED).",
        "timeout": f"No reply from {who}: the query for {host} timed out.",
        "unreachable": f"{who} is not accepting queries (port closed).",
        "nodata": f"{host} has no IPv4 (A) record: the answer came back empty.",
    }.get(kind, f"The DNS lookup for {host} failed.")

    if kind == "nodata" and aaaa["records"]:
        res.summary += f" It is IPv6-only ({aaaa['records'][0]}); this tool tests the IPv4 path."

    # Is it the name or the resolver? Ask independent public resolvers.
    if not ctx.resolver:
        public = {}
        for srv in PUBLIC_RESOLVERS:
            rec, p = _dig(host, "A", srv)
            res.commands.append(rec)
            public[srv] = {"status": p["status"], "a": p["records"]}
        res.details["public"] = public
        working = [s for s, p in public.items() if p["a"]]
        if working:
            res.details["error_kind"] = "local_resolver"
            ctx.ip = public[working[0]]["a"][0]
            res.summary += (
                f" Public resolver {working[0]} resolves it to {ctx.ip}, so the name is fine and "
                "your configured DNS server is the problem. Continuing with that address."
            )
        elif kind in ("timeout", "servfail") and all(p["status"] == "NXDOMAIN" for p in public.values()):
            res.details["error_kind"] = "nxdomain"
            res.summary = (
                f"{host} does not exist: public resolvers {' and '.join(public)} both answer NXDOMAIN "
                f"(your own resolver did not give a usable answer: {a['status']})."
            )
    return res


def _system_fallback(ctx: Context, res: CheckResult) -> CheckResult:
    host = ctx.target.host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        addrs = sorted({i[4][0] for i in infos})
        ctx.ip = addrs[0]
        res.status = Status.OK
        res.details = {"resolver": "system resolver", "a": addrs, "aaaa": [], "error_kind": None}
        res.summary = f"{host} resolves to {ctx.ip} (system resolver; dig is not installed)."
    except socket.gaierror as exc:
        res.status = Status.FAIL
        res.details = {"resolver": "system resolver", "a": [], "aaaa": [], "error_kind": "nxdomain"}
        res.summary = f"The system resolver could not resolve {host}: {exc.strerror or exc}."
    return res
