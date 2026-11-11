"""The command-line interface: argument handling, output formats and exit codes."""

import json

import pytest
from conftest import lab_capture

from nettriage import cli
from nettriage.checks.dns import check_dns
from nettriage.checks.base import Context
from nettriage.models import CheckResult, CommandRecord, Finding, Report, Status
from nettriage.render import Painter, render_markdown, render_terminal
from nettriage.util import parse_target


def sample_report(overall=Status.FAIL) -> Report:
    r = Report(id="abc", target=parse_target("https://shop.example"), started_at="2026-01-01T00:00:00+00:00", resolved_ip="203.0.113.10", overall=overall)
    r.headline = "DNS resolves fine, TCP 443 is open, but the TLS handshake fails because the certificate is expired."
    r.findings = [Finding("critical", "TLS_CERT_EXPIRED", "tls", "The certificate expired.", "verify code 10", "Renew it.")]
    r.checks = [CheckResult("tls", "TLS handshake and certificate", Status.FAIL, "expired", {}, [CommandRecord("openssl s_client", 0, "Verify return code: 10")], 42)]
    return r


@pytest.fixture
def fake_engine(monkeypatch):
    def run(target, on_event=None, **opts):
        report = sample_report()
        report.target = parse_target(target)
        run.opts = opts
        if on_event:
            on_event({"type": "start", "id": "abc", "target": report.target.url, "checks": []})
            on_event({"type": "check_finished", "check": report.checks[0].to_dict()})
        return report

    monkeypatch.setattr(cli, "run_diagnosis", run)
    return run


def test_bare_target_is_shorthand_for_diagnose(fake_engine, capsys):
    code = cli.main(["shop.example", "--no-color"])
    out = capsys.readouterr().out
    assert code == 2  # broken -> exit status 2, so scripts can gate on it
    assert "VERDICT: BROKEN" in out and "TLS_CERT_EXPIRED" in out and "Next step: Renew it." in out


def test_options_reach_the_engine(fake_engine):
    cli.main(["diagnose", "shop.example", "--ports", "22,8443", "--resolver", "10.0.0.53", "--tls-max", "1.2", "--skip", "mtr,mtu", "--json"])
    assert fake_engine.opts["ports"] == [22, 8443] and fake_engine.opts["resolver"] == "10.0.0.53"
    assert fake_engine.opts["tls_max"] == "1.2" and fake_engine.opts["skip"] == ("mtr", "mtu")


def test_json_output_is_machine_readable(fake_engine, capsys):
    cli.main(["shop.example", "--json"])
    assert json.loads(capsys.readouterr().out)["findings"][0]["code"] == "TLS_CERT_EXPIRED"


def test_markdown_and_saved_file(fake_engine, capsys, tmp_path):
    out_file = tmp_path / "r" / "report.md"
    cli.main(["shop.example", "--markdown", "-o", str(out_file)])
    assert "# Network diagnostic report: shop.example" in capsys.readouterr().out
    assert "## Evidence" in out_file.read_text()


def test_verbose_shows_the_commands_that_ran(fake_engine, capsys):
    cli.main(["shop.example", "-v", "--no-color"])
    assert "$ openssl s_client" in capsys.readouterr().out


def test_invalid_target_exits_cleanly(capsys):
    assert cli.main(["exa mple.com"]) == 64
    assert "error:" in capsys.readouterr().err


@pytest.mark.parametrize("ports", ["abc", "0", "70000", ""])
def test_bad_ports_are_rejected(ports):
    with pytest.raises(SystemExit):
        cli.main(["shop.example", "--ports", ports])


def test_pcap_command_on_a_lab_capture(capsys):
    assert cli.main(["pcap", str(lab_capture("02-tcp-reset")), "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "WHAT THE CAPTURE SHOWS" in out and "resets the connection" in out and "Wireshark filter:" in out


def test_pcap_command_json_and_missing_file(capsys, tmp_path):
    cli.main(["pcap", str(lab_capture("01-dns-failure")), "--json"])
    assert json.loads(capsys.readouterr().out)["packet_count"] == 4
    assert cli.main(["pcap", str(tmp_path / "nope.pcap")]) == 66


def test_renderers_cover_every_status():
    for status in (Status.OK, Status.WARN, Status.FAIL):
        report = sample_report(status)
        assert report.headline in render_terminal(report, Painter(True), verbose=True).replace("\n  ", " ")
        assert "| Check | Result | Time |" in render_markdown(report)


def test_ip_literal_skips_dns():
    ctx = Context(target=parse_target("https://127.0.0.1"))
    res = check_dns(ctx)
    assert res.status == Status.OK and ctx.ip == "127.0.0.1" and res.details["skipped_reason"] == "ip_literal"
