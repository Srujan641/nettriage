"""Local REST API for the web dashboard.

This service launches network probes on request, so it is meant to run on
localhost for its operator. It binds to 127.0.0.1 by default, validates every
target, and caps concurrent runs.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import re
import tempfile
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse

from . import __version__
from .engine import CHECKS, environment, run_diagnosis
from .pcap import PcapError, parse_pcap
from .render import render_markdown
from .util import TargetError, parse_target

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.environ.get("NETTRIAGE_DATA", ROOT / "backend" / "data"))
REPORTS_DIR = DATA_DIR / "reports"
LAB_DIR = Path(os.environ.get("NETTRIAGE_LABS", ROOT / "labs"))
DOCS_DIR = ROOT / "docs" / "scenarios"
MAX_CONCURRENT = 3
MAX_PCAP_BYTES = 25 * 1024 * 1024
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")

app = FastAPI(title="NetTriage API", version=__version__)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)


def _options(ports: str | None, resolver: str | None, tls_max: str | None, timeout: float) -> dict:
    opts: dict = {"timeout": min(max(timeout, 1.0), 15.0)}
    if ports:
        try:
            opts["ports"] = [int(p) for p in ports.split(",") if p.strip()]
        except ValueError:
            raise HTTPException(422, "ports must be comma-separated numbers") from None
        if len(opts["ports"]) > 32 or any(not 0 < p < 65536 for p in opts["ports"]):
            raise HTTPException(422, "give at most 32 ports between 1 and 65535")
    if resolver:
        try:
            opts["resolver"] = str(ipaddress.ip_address(resolver.strip()))
        except ValueError:
            raise HTTPException(422, "resolver must be an IP address") from None
    if tls_max:
        if tls_max not in ("1.1", "1.2"):
            raise HTTPException(422, "tls_max must be 1.1 or 1.2")
        opts["tls_max"] = tls_max
    return opts


def _save(report_dict: dict) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (REPORTS_DIR / f"{report_dict['id']}.json").write_text(json.dumps(report_dict))


def _load(report_id: str) -> dict:
    if not _ID.match(report_id):
        raise HTTPException(404, "report not found")
    path = REPORTS_DIR / f"{report_id}.json"
    if not path.is_file():
        raise HTTPException(404, "report not found")
    return json.loads(path.read_text())


# ----------------------------------------------------------------------- basics


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", **environment(), "checks": [{"id": i, "title": t} for i, t in CHECKS]}


@app.get("/api/diagnose/stream")
async def diagnose_stream(
    target: str = Query(..., max_length=2048),
    ports: str | None = None,
    resolver: str | None = None,
    tls_max: str | None = None,
    timeout: float = 5.0,
):
    """Server-sent events: one event per check as it finishes, then the full report."""
    try:
        parse_target(target)
    except TargetError as exc:
        raise HTTPException(422, str(exc)) from None
    opts = _options(ports, resolver, tls_max, timeout)
    if not _slots.acquire(blocking=False):
        raise HTTPException(429, f"{MAX_CONCURRENT} diagnostics are already running; try again in a moment")

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()

    def worker() -> None:
        try:
            def on_event(event: dict) -> None:
                if event["type"] == "report":
                    _save(event["report"])
                loop.call_soon_threadsafe(queue.put_nowait, event)

            run_diagnosis(target, on_event=on_event, **opts)
        except Exception as exc:
            loop.call_soon_threadsafe(queue.put_nowait, {"type": "error", "message": str(exc)})
        finally:
            _slots.release()
            loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=worker, daemon=True).start()

    async def events():
        while (event := await queue.get()) is not None:
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/diagnose")
def diagnose_once(body: dict) -> dict:
    """Blocking variant for scripts: returns the finished report."""
    target = str(body.get("target", ""))
    opts = _options(body.get("ports"), body.get("resolver"), body.get("tls_max"), float(body.get("timeout", 5.0)))
    if not _slots.acquire(blocking=False):
        raise HTTPException(429, "too many diagnostics running")
    try:
        report = run_diagnosis(target, **opts).to_dict()
    except TargetError as exc:
        raise HTTPException(422, str(exc)) from None
    finally:
        _slots.release()
    _save(report)
    return report


# ---------------------------------------------------------------------- history


@app.get("/api/reports")
def list_reports(limit: int = 50) -> list[dict]:
    if not REPORTS_DIR.is_dir():
        return []
    files = sorted(REPORTS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[: max(1, min(limit, 200))]
    out = []
    for f in files:
        try:
            r = json.loads(f.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        out.append({k: r.get(k) for k in ("id", "started_at", "duration_ms", "overall", "headline", "resolved_ip")} | {"target": r["target"]["url"]})
    return out


@app.get("/api/reports/{report_id}")
def get_report(report_id: str) -> dict:
    return _load(report_id)


@app.get("/api/reports/{report_id}/markdown")
def get_report_markdown(report_id: str):
    from fastapi.responses import PlainTextResponse

    from .models import CheckResult, CommandRecord, Finding, Report, Status, Target

    d = _load(report_id)
    target = Target(**{k: v for k, v in d["target"].items() if k != "url"})
    report = Report(
        id=d["id"], target=target, started_at=d["started_at"], duration_ms=d["duration_ms"], resolved_ip=d["resolved_ip"],
        overall=Status(d["overall"]), headline=d["headline"], findings=[Finding(**f) for f in d["findings"]],
        checks=[
            CheckResult(c["id"], c["title"], Status(c["status"]), c["summary"], c["details"], [CommandRecord(**x) for x in c["commands"]], c["duration_ms"])
            for c in d["checks"]
        ],
    )  # fmt: skip
    return PlainTextResponse(render_markdown(report), media_type="text/markdown")


@app.delete("/api/reports/{report_id}")
def delete_report(report_id: str) -> dict:
    _load(report_id)
    (REPORTS_DIR / f"{report_id}.json").unlink()
    return {"deleted": report_id}


# ------------------------------------------------------------------- lab + pcap


def _scenario_dir(scenario_id: str) -> Path:
    if not _ID.match(scenario_id) or not (LAB_DIR / "scenarios" / scenario_id / "scenario.json").is_file():
        raise HTTPException(404, "scenario not found")
    return LAB_DIR / "scenarios" / scenario_id


def _scenario_meta(scenario_id: str) -> dict:
    meta = json.loads((_scenario_dir(scenario_id) / "scenario.json").read_text())
    caps = LAB_DIR / "captures" / scenario_id
    labels = meta.get("captures") or {}
    files = sorted(p.name for p in caps.glob("*.pcap")) if caps.is_dir() else []
    files.sort(key=lambda n: list(labels).index(n) if n in labels else len(labels))
    meta["captures"] = [{"name": n, "label": labels.get(n, n)} for n in files]
    meta["has_report"] = (caps / "report.json").is_file()
    return meta


@app.get("/api/scenarios")
def list_scenarios() -> list[dict]:
    base = LAB_DIR / "scenarios"
    if not base.is_dir():
        return []
    return [_scenario_meta(d.name) for d in sorted(base.iterdir()) if (d / "scenario.json").is_file()]


@app.get("/api/scenarios/{scenario_id}")
def get_scenario(scenario_id: str) -> dict:
    meta = _scenario_meta(scenario_id)
    caps = LAB_DIR / "captures" / scenario_id
    writeup = DOCS_DIR / f"{scenario_id}.md"
    meta["writeup"] = writeup.read_text() if writeup.is_file() else ""
    meta["report"] = json.loads((caps / "report.json").read_text()) if meta["has_report"] else None
    return meta


@app.get("/api/scenarios/{scenario_id}/captures/{name}")
def scenario_capture(scenario_id: str, name: str, download: bool = False):
    _scenario_dir(scenario_id)
    if not re.fullmatch(r"[a-z0-9_-]{1,40}\.pcap", name):
        raise HTTPException(404, "capture not found")
    path = LAB_DIR / "captures" / scenario_id / name
    if not path.is_file():
        raise HTTPException(404, "capture not found")
    if download:
        return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=f"{scenario_id}-{name}")
    return parse_pcap(path)


@app.post("/api/pcap/analyze")
async def analyze_pcap(request: Request) -> dict:
    """Decode an uploaded capture. Send the raw file bytes as the request body."""
    body = await request.body()
    if not body:
        raise HTTPException(422, "empty upload")
    if len(body) > MAX_PCAP_BYTES:
        raise HTTPException(413, "capture is larger than 25 MB")
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        tmp.write(body)
        tmp.flush()
        try:
            result = parse_pcap(tmp.name)
        except PcapError as exc:
            raise HTTPException(422, str(exc)) from None
    result["file"] = request.headers.get("x-filename", "upload.pcap")[:120]
    return result


def serve(host: str = "127.0.0.1", port: int = 8000) -> int:
    import uvicorn

    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"warning: binding to {host} lets other machines launch network probes from this host.")
    uvicorn.run(app, host=host, port=port, log_level="info")
    return 0
