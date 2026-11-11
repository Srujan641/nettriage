"""Layer-3 checks run for real against the loopback address, so no internet is needed."""

import pytest

from nettriage.checks.base import Context
from nettriage.checks.network import builtin_mtr, check_mtr, check_mtu, check_ping, check_traceroute
from nettriage.checks.ports import check_ports, probe_port
from nettriage.models import Status
from nettriage.util import parse_target


@pytest.fixture
def ctx():
    c = Context(target=parse_target("http://127.0.0.1:9"), ip="127.0.0.1", ports=[9], timeout=2)
    return c


def test_ping_loopback(ctx):
    res = check_ping(ctx)
    assert res.status == Status.OK and res.details["received"] == res.details["sent"] == 5
    assert res.details["rtt"]["avg"] < 50 and res.commands[0].command.startswith("ping")


def test_traceroute_loopback(ctx):
    res = check_traceroute(ctx)
    if res.status == Status.SKIP:
        pytest.skip("traceroute not installed")
    assert res.details["reached"] and res.details["hops"][0]["ip"] == "127.0.0.1"


def test_builtin_mtr_reaches_loopback_in_one_hop():
    hops = builtin_mtr("127.0.0.1", cycles=3)
    if hops is None:
        pytest.skip("no ICMP socket available to this user")
    assert len(hops) == 1 and hops[0]["ip"] == "127.0.0.1" and hops[0]["loss_pct"] == 0 and hops[0]["sent"] == 3


def test_mtr_check_reports_no_loss(ctx):
    res = check_mtr(ctx)
    if res.status == Status.SKIP:
        pytest.skip("no mtr and no ICMP socket")
    assert res.status == Status.OK and res.details["reached"] and res.details["end_to_end_loss_pct"] == 0


def test_path_mtu_on_loopback_is_not_a_black_hole(ctx):
    res = check_mtu(ctx)
    assert res.status == Status.OK and res.details["path_mtu"] == 1500 and res.details["blackhole"] is False


def test_closed_port_is_reported_as_reset(ctx):
    assert probe_port("127.0.0.1", 9, 2)["state"] == "closed"
    res = check_ports(ctx)
    assert res.status == Status.FAIL and "closed" in res.summary


def test_filtered_port_is_reported_as_silence():
    # 192.0.2.0/24 is reserved for documentation (RFC 5737): nothing answers there.
    probe = probe_port("192.0.2.1", 443, 1)
    assert probe["state"] in ("filtered", "unreachable")
