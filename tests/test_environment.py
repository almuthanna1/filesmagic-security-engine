"""The measurements that decide when a test may skip for an unsupported environment
(tests/environment.py): a skip needs the condition demonstrated, and CI turns every one into a failure."""

import re

import pytest

from tests import environment as env

DEV = """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
"""
ETH = DEV + "  eth0:    9999      99    0    0    0     0          0         0     9999      99    0    0    0     0       0          0\n"
ROUTE_HEADER = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
V6_LO = "00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo\n"


def net(tmp_path, dev=DEV, route=ROUTE_HEADER, v6=V6_LO):
    for name, text in (("dev", dev), ("route", route), ("ipv6_route", v6)):
        (tmp_path / name).write_text(text)
    return tmp_path


def test_an_offline_namespace_is_recognised(tmp_path):
    assert env.offline_host(net(tmp_path)).startswith("offline host: interfaces ['lo']")


@pytest.mark.parametrize("change", [
    {"dev": ETH},  # a second interface
    {"route": ROUTE_HEADER + "eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"},  # a default route
    {"v6": V6_LO + V6_LO.replace("       lo", "     eth0")},  # an IPv6 route off lo
])
def test_any_interface_or_route_beyond_loopback_is_not_offline(tmp_path, change):
    assert env.offline_host(net(tmp_path, **change)) is None


def test_an_unreadable_measurement_is_not_offline(tmp_path):
    assert env.offline_host(tmp_path / "missing") is None


def test_exec_denied_needs_an_enforced_profile(monkeypatch):
    for label in (None, "unconfined", "filesmagic-eval-python (complain)"):
        monkeypatch.setattr(env, "apparmor_label", lambda label=label: label)
        assert env.exec_denied("bash") is None


def test_exec_denied_needs_the_exec_to_be_refused(monkeypatch):
    monkeypatch.setattr(env, "apparmor_label", lambda: "filesmagic-eval-python (enforce)")
    monkeypatch.setattr(env.subprocess, "run", lambda *a, **k: None)  # starts fine
    assert env.exec_denied("bash") is None

    def refused(*a, **k):
        raise PermissionError(13, "Permission denied", "bash")
    monkeypatch.setattr(env.subprocess, "run", refused)
    assert "denies starting bash" in env.exec_denied("bash")


def test_unsupported_skips_with_a_marked_reason_but_fails_where_required(monkeypatch):
    monkeypatch.setattr(env, "REQUIRED", False)
    with pytest.raises(pytest.skip.Exception, match=re.escape(env.UNSUPPORTED)):
        env.unsupported("x")
    monkeypatch.setattr(env, "REQUIRED", True)
    with pytest.raises(pytest.fail.Exception, match=re.escape(env.UNSUPPORTED)):
        env.unsupported("x")
