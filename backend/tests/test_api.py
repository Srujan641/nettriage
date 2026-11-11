import json

import pytest
from conftest import checksum_free_ip as ip
from conftest import tcp, write_pcap
from fastapi.testclient import TestClient

from nettriage import api
from nettriage.models import Report, Status
from nettriage.util import parse_target


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "REPORTS_DIR", tmp_path / "reports")

    def fake_run(target, on_event=None, **opts):
        report = Report(id="abc123def456", target=parse_target(target), started_at="2026-01-01T00:00:00+00:00", overall=Status.OK, headline="Everything checks out.")
        if on_event:
            on_event({"type": "start", "id": report.id, "target": report.target.url, "checks": []})
            on_event({"type": "report", "report": report.to_dict()})
        return report

    monkeypatch.setattr(api, "run_diagnosis", fake_run)
    return TestClient(api.app)


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok" and "dig" in body["tools"] and len(body["checks"]) == 8


def test_stream_emits_events_and_saves_the_report(client):
    resp = client.get("/api/diagnose/stream", params={"target": "example.com"})
    assert resp.status_code == 200 and resp.headers["content-type"].startswith("text/event-stream")
    events = [json.loads(line[6:]) for line in resp.text.splitlines() if line.startswith("data: ")]
    assert [e["type"] for e in events] == ["start", "report"]
    assert client.get("/api/reports").json()[0]["target"] == "https://example.com/"
    assert client.get("/api/reports/abc123def456").json()["headline"] == "Everything checks out."
    assert "# Network diagnostic report" in client.get("/api/reports/abc123def456/markdown").text


@pytest.mark.parametrize("target", ["", "-oX evil", "exa mple.com", "ftp://x.com"])
def test_bad_targets_are_rejected_before_anything_runs(client, target):
    assert client.get("/api/diagnose/stream", params={"target": target}).status_code == 422


@pytest.mark.parametrize("params", [{"ports": "80,abc"}, {"ports": "70000"}, {"resolver": "not-an-ip"}, {"resolver": "1.1.1.1; id"}, {"tls_max": "0.9"}])
def test_bad_options_are_rejected(client, params):
    assert client.get("/api/diagnose/stream", params={"target": "example.com", **params}).status_code == 422


@pytest.mark.parametrize("rid", ["../../etc/passwd", "..%2F..%2Fsecret", "ABC", "x" * 60])
def test_report_ids_cannot_escape_the_data_directory(client, rid):
    assert client.get(f"/api/reports/{rid}").status_code == 404


def test_pcap_upload(client, tmp_path):
    f = write_pcap(tmp_path / "c.pcap", [(0, ip("10.0.0.1", "10.0.0.2", 6, tcp(1234, 443, 1, 0, 0x02)))])
    resp = client.post("/api/pcap/analyze", content=f.read_bytes(), headers={"x-filename": "mine.pcap"})
    assert resp.status_code == 200 and resp.json()["packet_count"] == 1 and resp.json()["file"] == "mine.pcap"
    assert client.post("/api/pcap/analyze", content=b"garbage-garbage-garbage-garbage").status_code == 422


def test_scenarios_are_listed(client):
    ids = [s["id"] for s in client.get("/api/scenarios").json()]
    assert ids[:2] == ["00-baseline", "01-dns-failure"] and len(ids) == 5
    assert client.get("/api/scenarios/02-tcp-reset").json()["expect"] == "HTTP_RESET"
    assert client.get("/api/scenarios/nope").status_code == 404
    assert client.get("/api/scenarios/02-tcp-reset/captures/..%2Fx.pcap").status_code == 404
