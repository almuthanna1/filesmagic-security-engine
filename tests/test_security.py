"""Access control, worker isolation and resource limits. All inputs are inert fixtures."""

import asyncio
import errno
import functools
import hashlib
import socket
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import auth, main, worker
from app.models import Verdict, WorkerReport
from tests.office_fixtures import make_ooxml
from tests.pdf_fixtures import make_pdf
from tests.scan_client import KEY, auth_headers, post_scan

client = TestClient(main.app)
DATA = b"hello world"


def scan_with_token(token, data=DATA):
    return client.post("/scan", content=data, headers={"Authorization": f"Bearer {token}"})


def token(data=DATA, **kw):
    return auth.mint_token(KEY, hashlib.sha256(data).hexdigest(), len(data), **kw)


# --------------------------------------------------------------------- authorization


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"},
                                     {"Authorization": "Bearer not.a-token"}, {"Authorization": "Bearer " + "a" * 5000}])
def test_requests_without_valid_token_are_rejected(headers):
    r = client.post("/scan", content=DATA, headers=headers)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_token_signed_by_another_key_is_rejected():
    forged = auth.mint_token(Ed25519PrivateKey.generate(), hashlib.sha256(DATA).hexdigest(), len(DATA))
    assert scan_with_token(forged).status_code == 401


def test_tampered_claims_are_rejected():
    _, sig = token().split(".")
    other_payload = token(b"other file").split(".")[0]
    assert scan_with_token(f"{other_payload}.{sig}").status_code == 401


def test_expired_and_overlong_tokens_are_rejected():
    assert scan_with_token(token(now=time.time() - 200)).status_code == 401
    assert scan_with_token(token(lifetime=3600)).status_code == 401


def test_token_for_wrong_audience_is_rejected(monkeypatch):
    audience = auth.AUDIENCE
    monkeypatch.setattr(auth, "AUDIENCE", "some-other-service")
    t = token()
    monkeypatch.setattr(auth, "AUDIENCE", audience)
    assert scan_with_token(t).status_code == 401


def test_token_is_single_use():
    t = token()
    assert scan_with_token(t).status_code == 200
    r = scan_with_token(t)
    assert r.status_code == 401 and "already been used" in r.json()["detail"]


def test_token_is_bound_to_one_file():
    r = scan_with_token(token(b"the approved file"), data=b"a different file")
    assert r.status_code == 403


def test_unconfigured_engine_refuses_every_scan(monkeypatch):
    monkeypatch.setattr(auth, "PUBLIC_KEY", None)
    r = post_scan(client, DATA)
    assert r.status_code == 401 and "no token verification key" in r.json()["detail"]
    assert client.get("/health").json()["auth_configured"] is False


def test_authorization_is_checked_before_size(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)
    assert client.post("/scan", content=b"x" * 100).status_code == 401


def test_repeated_unauthorized_requests_are_throttled():
    for _ in range(auth.MAX_FAILURES_PER_MINUTE):
        assert client.post("/scan", content=DATA).status_code == 401
    r = post_scan(client, DATA)  # even a valid token is refused while throttled
    assert r.status_code == 429 and r.headers["retry-after"] == "60"


def test_throttling_is_per_client_address():
    for _ in range(auth.MAX_FAILURES_PER_MINUTE):
        client.post("/scan", content=DATA, headers={"X-Forwarded-For": "203.0.113.9"})
    # A spoofed leading X-Forwarded-For entry does not escape the limit.
    blocked = client.post("/scan", content=DATA, headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.9"})
    assert blocked.status_code == 429
    assert post_scan(client, DATA).status_code == 200  # other addresses are unaffected


def test_failures_expire_after_a_minute():
    for _ in range(auth.MAX_FAILURES_PER_MINUTE):
        auth.record_failure("c", now=1000)
    assert auth.too_many_failures("c", now=1030)
    assert not auth.too_many_failures("c", now=1061)


def test_cors_preflight_allows_token_header_from_lab_only():
    preflight = {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,x-filename"}
    ok = client.options("/scan", headers=preflight | {"Origin": "http://localhost:3000"})
    assert ok.status_code == 200 and "authorization" in ok.headers["access-control-allow-headers"].lower()
    assert client.options("/scan", headers=preflight | {"Origin": "https://evil.example"}).status_code == 400


# --------------------------------------------------------------------- resource limits


def test_concurrent_scans_are_limited(monkeypatch):
    monkeypatch.setattr(main, "_active_scans", main.MAX_CONCURRENT_SCANS)
    r = post_scan(client, DATA)
    assert r.status_code == 429 and "busy" in r.json()["detail"]


def test_scan_slot_is_released_after_failures(monkeypatch):
    async def explode(data):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(main, "run_scan", explode)
    with pytest.raises(RuntimeError):
        post_scan(client, DATA)
    assert main._active_scans == 0


def test_slow_upload_times_out(monkeypatch):
    class SlowRequest:
        async def stream(self):
            yield b"x"
            await asyncio.sleep(5)
            yield b"y"

    monkeypatch.setattr(main, "UPLOAD_TIMEOUT_SECONDS", 0.1)
    with pytest.raises(main.HTTPException) as e:
        asyncio.run(main.read_body(SlowRequest(), 100))
    assert e.value.status_code == 408


def test_upload_is_never_spooled_to_disk(monkeypatch):
    import tempfile

    def forbidden(*a, **kw):
        raise AssertionError("upload written to a temporary file")

    for name in ("SpooledTemporaryFile", "NamedTemporaryFile", "TemporaryFile", "mkstemp"):
        monkeypatch.setattr(tempfile, name, forbidden)
    assert post_scan(client, make_ooxml({})).json()["verdict"] == Verdict.SAFE


# --------------------------------------------------------------------- the isolated worker (real subprocesses)


def run_fake(mode, timeout=10.0):
    cmd = [sys.executable, "-B", "-m", "tests.fake_worker", mode]
    return asyncio.run(worker.run(DATA, cmd=cmd, timeout=timeout))


def test_real_worker_scans_benign_documents():
    for data in (make_ooxml({}), make_pdf(), DATA):
        report = asyncio.run(worker.run(data))
        assert {s.name for s in report.scanners} == {"yara-x", "office", "pdf"}
        assert all(s.status != "failed" for s in report.scanners)
        assert report.findings == []
        assert report.isolation["process"] and report.isolation["audit_hook"]


def test_real_worker_detects_through_the_api(monkeypatch):
    monkeypatch.setattr(main, "run_scan", worker.run)
    body = post_scan(client, make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>"), "launch.pdf").json()
    assert body["verdict"] == Verdict.MALICIOUS and body["complete"]
    assert body["detected_format"] == "pdf" and body["isolation"]["process"]
    assert body["sha256"] == hashlib.sha256(make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>")).hexdigest()
    assert body["versions"]["ruleset_sha256"] == main.ruleset_hash()


def test_real_worker_reports_failure_classification():
    report = asyncio.run(worker.run(b"%PDF-1.4\nnot really a PDF\n"))
    status = {s.name: s for s in report.scanners}["pdf"]
    assert status.status == "failed" and status.error_kind == "malformed_input" and status.error_type
    assert report.traces == {}  # traces are only kept for unexpected failures


def test_worker_timeout_is_enforced():
    start = time.monotonic()
    with pytest.raises(worker.WorkerError, match="timed out"):
        run_fake("sleep", timeout=1)
    assert time.monotonic() - start < 10


@pytest.mark.parametrize("mode, message", [("crash", "exited abnormally"), ("flood", "too much output"),
                                           ("garbage", "invalid report")])
def test_misbehaving_worker_fails_closed(mode, message):
    with pytest.raises(worker.WorkerError, match=message):
        run_fake(mode)


@pytest.mark.parametrize("mode", ["crash", "sleep", "garbage"])
def test_worker_failure_is_unable_to_scan_not_an_api_crash(monkeypatch, mode):
    cmd = [sys.executable, "-B", "-m", "tests.fake_worker", mode]
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=cmd, timeout=1))
    r = post_scan(client, DATA)
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and not body["complete"]
    assert all(s["status"] == "failed" for s in body["scanners"])
    assert client.get("/health").status_code == 200  # the API survived


def test_worker_reporting_unexpected_scanners_is_rejected(monkeypatch):
    async def liar(data):
        return worker.WorkerReport(scanners=[], findings=[])  # "nothing applied", hiding every scanner

    monkeypatch.setattr(main, "run_scan", liar)
    assert post_scan(client, DATA).json()["verdict"] == Verdict.UNABLE_TO_SCAN


def test_worker_environment_carries_no_secrets(monkeypatch):
    monkeypatch.setenv("SECURITY_ENGINE_TOKEN_PUBLIC_KEY", "x")
    monkeypatch.setenv("SOME_API_SECRET", "x")
    assert set(worker.child_env()) <= {"SYSTEMROOT"}


AUDIT_PROBE = """
import os, socket, subprocess, sys, tempfile
probe = os.path.join(tempfile.gettempdir(), "fm-probe.txt")  # gettempdir() itself writes, so resolve it first
from app.worker import _audit_hook
sys.addaudithook(_audit_hook)
def blocked(f):
    try:
        f()
    except PermissionError:
        return True
    return False
checks = {
    "socket": lambda: socket.socket(),
    "dns": lambda: socket.getaddrinfo("example.com", 443),
    "subprocess": lambda: subprocess.run([sys.executable, "-c", "pass"]),
    "system": lambda: os.system("echo hi"),
    "write": lambda: open(probe, "w"),
    "os.open": lambda: os.open(probe, os.O_CREAT | os.O_WRONLY),
    "remove": lambda: os.remove("nothing"),
}
failed = [name for name, f in checks.items() if not blocked(f)]
open(__import__("app").__file__).read()  # reading stays allowed
print("ALLOWED:" + ",".join(failed))
"""


def test_audit_hook_blocks_network_processes_and_writes():
    # In a separate interpreter: an audit hook can never be removed from the process it is added to.
    out = subprocess.run([sys.executable, "-B", "-c", AUDIT_PROBE], cwd=worker.APP_ROOT, capture_output=True,
                         text=True, timeout=60)
    assert out.stdout.strip() == "ALLOWED:", out.stdout + out.stderr


def test_isolation_can_be_required(monkeypatch):
    # A strict worker either has every control and scans normally, or refuses to analyse
    # anything (e.g. on Windows, or a host without namespaces). Both outcomes are asserted.
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    report = asyncio.run(worker.run(make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>")))
    if not worker.missing_controls(report.isolation):
        assert all(s.status != "failed" for s in report.scanners)
        assert {f.rule_id for f in report.findings} == {"PDF_Launch_Action", "PDF_LAUNCH_ACTION"}
    else:
        assert all(s.status == "failed" and "required isolation unavailable" in s.error for s in report.scanners)
        assert report.findings == []


# --------------------------------------------------------------------- safe errors and logging


def test_scanner_errors_do_not_leak_paths_or_tracebacks(monkeypatch):
    class Leaky:
        name = "leaky"

        def scan(self, filename, data):
            raise FileNotFoundError(r"/srv/app/secrets/config.py and C:\Users\dev\key.pem missing")

    monkeypatch.setattr(main, "SCANNERS", [Leaky()])
    body = post_scan(client, DATA).json()
    error = body["scanners"][0]["error"]
    assert "/srv" not in error and "Users" not in error and "<path>" in error
    assert "Traceback" not in str(body)


def test_logs_never_contain_file_contents_or_names(caplog):
    caplog.set_level("DEBUG")
    secret = b"%PDF-1.7 SECRET-CONTENT-MARKER /Launch"
    post_scan(client, secret, "attacker\nname.pdf")
    client.post("/scan", content=secret, headers={"Authorization": "Bearer attacker-injected"})
    logs = caplog.text
    assert "SECRET-CONTENT-MARKER" not in logs and "attacker" not in logs and "name.pdf" not in logs
    assert "verdict=MALICIOUS" in logs


def test_filename_is_sanitised():
    r = client.post("/scan", content=DATA, headers=auth_headers(DATA) | {"X-Filename": "a%0Ab%00c" + "x" * 400})
    assert r.json()["filename"].startswith("a?b?c") and len(r.json()["filename"]) == 255


def test_no_outbound_connections_during_scans(monkeypatch):
    import socket

    real_connect = socket.socket.connect

    def connect(sock, address):  # the event loop may use a loopback socket pair internally
        if address[0] not in ("127.0.0.1", "::1"):
            raise AssertionError(f"outbound connection attempted to {address!r}")
        return real_connect(sock, address)

    def getaddrinfo(*a, **kw):
        raise AssertionError("DNS lookup attempted")

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    for data in (make_ooxml({}), make_pdf("/OpenAction << /S /URI /URI (https://filesmagic.example/x) >>"), DATA):
        assert post_scan(client, data).status_code == 200


# --------------------------------------------------------------------- rule-set hash (Phase C5)


def test_ruleset_hash_ignores_line_endings(tmp_path):
    rules = b'rule a { condition: true }\nrule b { condition: false }\n'
    hashes = []
    for name, content in [("lf", rules), ("crlf", rules.replace(b"\n", b"\r\n")), ("cr", rules.replace(b"\n", b"\r"))]:
        d = tmp_path / name
        d.mkdir()
        (d / "r.yar").write_bytes(content)
        hashes.append(main.ruleset_hash(d))
    assert len(set(hashes)) == 1
    changed = tmp_path / "changed"
    changed.mkdir()
    (changed / "r.yar").write_bytes(rules.replace(b"true", b"false"))
    assert main.ruleset_hash(changed) != hashes[0]


# --------------------------------------------------------------------- network isolation verification (Phase C5)

IPV4_ROUTES = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
eth0\t0000A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0
"""
IPV6_ROUTES = """fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000001 00000000 80200001       lo
"""


def test_usable_routes_counts_only_outbound_routes():
    assert worker.usable_routes(IPV4_ROUTES, 3, 0, header=True) == 2
    assert worker.usable_routes(IPV4_ROUTES.splitlines()[0], 3, 0, header=True) == 0  # header only
    assert worker.usable_routes("", 3, 0, header=True) == 0
    # IPv6: the eth0 route counts; the reject (unreachable) entry and the loopback route do not.
    assert worker.usable_routes(IPV6_ROUTES, 8, 9, header=False) == 1
    assert worker.usable_routes("\n".join(IPV6_ROUTES.splitlines()[1:]), 8, 9, header=False) == 0


class FakeSocket:
    def __init__(self, error=None):
        self.error = error

    def __call__(self, family, kind):
        if isinstance(self.error, tuple) and self.error[0] == "create":
            raise OSError(self.error[1], "fake")
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def connect(self, address):
        if isinstance(self.error, int):
            raise OSError(self.error, "fake")


@pytest.mark.parametrize("error, family, expected", [
    (errno.ENETUNREACH, socket.AF_INET, True),
    (errno.EHOSTUNREACH, socket.AF_INET, True),
    (None, socket.AF_INET, False),  # a route exists
    (errno.ECONNREFUSED, socket.AF_INET, False),  # anything else is not proof of isolation
    (("create", errno.EAFNOSUPPORT), socket.AF_INET6, True),  # no IPv6 at all
    (("create", errno.EAFNOSUPPORT), socket.AF_INET, False),
])
def test_route_lookup_check(monkeypatch, error, family, expected):
    monkeypatch.setattr(socket, "socket", FakeSocket(error))
    assert worker._route_lookup_fails(family, ("192.0.2.1", 9)) is expected


def test_network_verification_fails_closed_on_unexpected_errors(monkeypatch):
    def broken():
        raise OSError("netlink unavailable")

    monkeypatch.setattr(socket, "if_nameindex", broken)
    checks = worker.verify_network_isolation()
    assert set(checks) == set(worker.NETWORK_CHECKS) and not any(checks.values())


# The two valid interface states: only loopback, or loopback plus the inert fallback tunnel.
LOOPBACK = dict.fromkeys(worker.NETWORK_CHECKS, True) | {"net_fallback_tunnel_inert": False}
TUNNEL = dict.fromkeys(worker.NETWORK_CHECKS, True) | {"net_loopback_only": False}
STATES = pytest.mark.parametrize("state", [LOOPBACK, TUNNEL], ids=["loopback-only", "fallback-tunnel"])


def test_network_isolation_without_namespace_reports_everything_missing():
    def must_not_run():
        raise AssertionError("verification must not run outside a namespace")

    for enter in (lambda: False, lambda: (_ for _ in ()).throw(OSError("unshare denied"))):
        result = worker.network_isolation(enter=enter, verify=must_not_run)
        assert result == {"network_namespace": False, "network_verified": False, "net_interfaces_safe": False,
                          **dict.fromkeys(worker.NETWORK_CHECKS, False)}


@STATES
def test_network_isolation_with_verified_namespace(state):
    result = worker.network_isolation(enter=lambda: True, verify=lambda: dict(state))
    assert result["network_namespace"] and result["net_interfaces_safe"] and result["network_verified"]
    assert {k: result[k] for k in worker.NETWORK_CHECKS} == state  # reported as found, never rewritten


@pytest.mark.parametrize("both", [True, False])
def test_network_isolation_needs_exactly_one_interface_state(both):
    # Neither state (e.g. an unknown interface) fails; both at once is contradictory and fails too.
    checks = dict(LOOPBACK, net_loopback_only=both, net_fallback_tunnel_inert=both)
    result = worker.network_isolation(enter=lambda: True, verify=lambda: checks)
    assert result["net_interfaces_safe"] is False and result["network_verified"] is False
    assert all(result[k] for k in worker.ROUTE_CHECKS)


@STATES
@pytest.mark.parametrize("failed", worker.ROUTE_CHECKS)
def test_network_isolation_one_failed_route_check_is_not_verified(state, failed):
    checks = dict(state, **{failed: False})
    result = worker.network_isolation(enter=lambda: True, verify=lambda: checks)
    assert result["network_namespace"] is True and result["net_interfaces_safe"] is True
    assert result["network_verified"] is False
    assert result[failed] is False and sum(not result[k] for k in worker.ROUTE_CHECKS) == 1


def test_network_isolation_only_literal_true_counts():
    # Missing or non-boolean check values are failures, never passes.
    result = worker.network_isolation(enter=lambda: True, verify=lambda: {"net_loopback_only": 1})
    assert result["network_verified"] is False and result["net_interfaces_safe"] is False
    assert not any(result[k] for k in worker.NETWORK_CHECKS)


def test_real_worker_network_report_is_consistent():
    # Holds on every host: verified exactly when the interfaces are safe and every route check
    # passes, the interface state is never both, and no check passes without a namespace.
    iso = asyncio.run(worker.run(DATA)).isolation
    assert set(iso) == set(worker.ISOLATION_CONTROLS)
    assert iso["network_verified"] == (iso["net_interfaces_safe"] and all(iso[k] for k in worker.ROUTE_CHECKS))
    if iso["network_namespace"]:
        assert iso["net_interfaces_safe"] == (iso["net_loopback_only"] != iso["net_fallback_tunnel_inert"])
    else:
        assert not iso["network_verified"] and not iso["net_interfaces_safe"]
        assert not any(iso[k] for k in worker.NETWORK_CHECKS)


def test_scan_result_reports_configured_strict_mode(monkeypatch):
    assert post_scan(client, DATA).json()["isolation_required"] is False
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    assert post_scan(client, DATA).json()["isolation_required"] is True


# --------------------------------------------------------------------- network diagnostics (Phase C7B, staging only)


ROUTE_HEADER = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
DEFAULT_ROUTE = "{dev}\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n"
LO = {"up": False, "running": False, "loopback": True, "link_type": 772, "ipv4_address": False}
SIT = {"up": False, "running": False, "loopback": False, "link_type": 776, "ipv4_address": False}


def fake_namespace(monkeypatch, interfaces, routes="", if_inet6="", names=None, dev=None):
    """A namespace described by {name: ioctl state}; nothing real is queried. names overrides the
    interface list and dev the /proc/net/dev names (None as a file: it cannot be read)."""
    if callable(interfaces):
        monkeypatch.setattr(socket, "if_nameindex", interfaces)
        names = []
    else:
        names = list(interfaces) if names is None else names
        monkeypatch.setattr(socket, "if_nameindex", lambda: [(i + 1, n) for i, n in enumerate(names)])
        monkeypatch.setattr(worker, "_interface_state", lambda name: dict(interfaces[name]))
    dev_text = None if dev == "unreadable" else "Inter-|\n face |\n" + "".join(
        f"  {n}: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n" for n in (names if dev is None else dev))
    files = {"/proc/net/route": ROUTE_HEADER + routes, "/proc/net/ipv6_route": "", "/proc/net/if_inet6": if_inet6,
             "/proc/net/dev": dev_text}

    def read(path, missing_ok=False):
        if files[path] is None:
            raise FileNotFoundError(path)
        return files[path]

    monkeypatch.setattr(worker, "_read", read)
    monkeypatch.setattr(worker, "_route_lookup_fails", lambda family, address: not routes)


def test_diagnostics_only_loopback(monkeypatch):
    fake_namespace(monkeypatch, {"lo": LO})
    diag = worker.collect_diagnostics()
    assert diag.interface_count == 1 and [i.name for i in diag.interfaces] == ["lo"]
    assert diag.interfaces[0].loopback and diag.usable_routes_v4 == 0 and diag.usable_routes_v6 == 0
    assert worker.network_isolation(enter=lambda: True)["network_verified"] is True


def test_diagnostics_extra_interface_is_reported_and_still_fails(monkeypatch):
    fake_namespace(monkeypatch, {"lo": LO, "sit0": SIT})
    diag = worker.collect_diagnostics()
    sit0 = diag.interfaces[1]
    assert (sit0.index, sit0.name, sit0.up, sit0.link_type, sit0.ipv4_address) == (2, "sit0", False, 776, False)
    assert sit0.usable_routes_v4 == 0 and sit0.ipv6_addresses == 0
    # The diagnostics describe the extra interface; they never excuse it.
    result = worker.network_isolation(enter=lambda: True)
    assert result["net_loopback_only"] is False and result["network_verified"] is False


def test_diagnostics_attribute_usable_routes_to_their_interface(monkeypatch):
    fake_namespace(monkeypatch, {"lo": LO, "eth0": dict(SIT, up=True, link_type=1, ipv4_address=True)},
                   routes=DEFAULT_ROUTE.format(dev="eth0"))
    diag = worker.collect_diagnostics()
    assert diag.usable_routes_v4 == 1 and [i.usable_routes_v4 for i in diag.interfaces] == [0, 1]
    assert not any(worker.verify_network_isolation()[k] for k in ("net_loopback_only", "net_ipv4_no_route"))


def test_diagnostics_enumeration_failure(monkeypatch):
    def broken():
        raise OSError(errno.EPERM, "denied")

    fake_namespace(monkeypatch, broken)
    diag = worker.collect_diagnostics()
    assert (diag.enumeration_error, diag.enumeration_errno, diag.interface_count, diag.interfaces) == \
        ("PermissionError", "EPERM", 0, [])
    assert not any(worker.verify_network_isolation().values())


def test_diagnostics_sanitise_and_bound_malformed_interface_data(monkeypatch):
    pairs = [("7", "bad\nname"), (-5, "x" * 40), (3, ""), (4, "a b/../c")] + [(10 + i, f"if{i}") for i in range(30)]
    fake_namespace(monkeypatch, lambda: pairs)
    monkeypatch.setattr(worker, "_interface_state", lambda name: {"error": "ENODEV"})
    diag = worker.collect_diagnostics()
    assert diag.collection_error is None and diag.interface_count == 34 and len(diag.interfaces) == 16
    assert [(i.index, i.name) for i in diag.interfaces[:4]] == [(-1, "bad?name"), (-1, "x" * 15), (3, "?"),
                                                              (4, "a?b?..?c")]


def test_diagnostics_faults_never_break_a_scan():
    def crash():
        raise RuntimeError("injected")

    assert worker.collect_diagnostics(crash).collection_error == "RuntimeError"
    # Values that escape sanitisation are rejected as a whole, not passed on to the log.
    junk = {"interfaces": [{"index": 1, "name": "lo\nFAKE LOG LINE"}]}
    assert worker.collect_diagnostics(lambda: junk).collection_error == "ValidationError"


def test_worker_report_rejects_injected_diagnostics():
    report = {"scanners": [], "findings": [], "diagnostics": {"interfaces": [{"index": 1, "name": "a\nb"}]}}
    with pytest.raises(ValidationError):
        WorkerReport.model_validate(report)
    with pytest.raises(ValidationError):
        WorkerReport.model_validate({"scanners": [], "findings": [], "diagnostics": {"secret": "x"}})


def test_diagnostics_are_off_unless_configured(monkeypatch):
    assert "--net-diagnostics" not in worker.command()
    monkeypatch.setattr(worker, "NET_DIAGNOSTICS", True)
    assert worker.command()[-1] == "--net-diagnostics"


# The real worker in a fresh interpreter, with an extra interface injected into its namespace view.
EXTRA_INTERFACE_WORKER = """import os, socket, sys
import app.worker as w
real_enter = w._network_namespace
w.POSIX = True
w._network_namespace = lambda: (os.name == "posix" and real_enter()) or True
real = socket.if_nameindex if hasattr(socket, "if_nameindex") else (lambda: [(1, "lo")])
socket.if_nameindex = lambda: [p for p in real() if p[1] == "lo"] + [(99, "sit0")]
w._interface_state = lambda name: {"up": False, "loopback": name == "lo"}
sys.exit(w.main(["--require-isolation", "--net-diagnostics"]))"""


def test_strict_mode_with_diagnostics_fails_closed_and_logs_only(monkeypatch, caplog):
    cmd = [sys.executable, "-B", "-c", EXTRA_INTERFACE_WORKER]
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=cmd))
    with caplog.at_level("WARNING", logger="app.main"):
        r = post_scan(client, make_pdf())
    body = r.json()
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and body["findings"] == [] and not body["complete"]
    assert body["isolation"]["net_loopback_only"] is False and body["isolation"]["network_verified"] is False
    assert all("net_interfaces_safe" in s["error"] for s in body["scanners"])
    assert body["isolation"]["net_fallback_tunnel_inert"] is False and "net_interfaces_safe" in body["isolation_missing"]
    assert "diagnostics" not in body and "sit0" not in r.text
    lines = [m for m in caplog.messages if m.startswith("network diagnostics request_id=" + body["request_id"])]
    assert len(lines) == 1 and '"name":"sit0"' in lines[0] and '"index":99' in lines[0]


# --------------------------------------------------------------------- interface policy (Phase C7C)


TUNL0 = {"up": False, "running": False, "loopback": False, "link_type": 768, "ipv4_address": False}  # as on Render


def isolation_of(monkeypatch, interfaces, **kw):
    fake_namespace(monkeypatch, interfaces, **kw)
    return worker.network_isolation(enter=lambda: True)


def test_policy_accepts_loopback_only(monkeypatch):
    result = isolation_of(monkeypatch, {"lo": LO})
    assert result["net_loopback_only"] is True and result["net_fallback_tunnel_inert"] is False
    assert result["net_interfaces_safe"] is True and result["network_verified"] is True


def test_policy_accepts_loopback_plus_inert_fallback_tunnel(monkeypatch):
    result = isolation_of(monkeypatch, {"lo": LO, "tunl0": TUNL0})
    # Truthful: the namespace is not loopback-only; it is the verified inert-tunnel state.
    assert result["net_loopback_only"] is False and result["net_fallback_tunnel_inert"] is True
    assert result["net_interfaces_safe"] is True and result["network_verified"] is True


@pytest.mark.parametrize("interfaces, kw", [
    ({"lo": LO, "eth0": dict(TUNL0, link_type=1)}, {}),  # unknown interface
    ({"lo": LO, "sit0": SIT}, {}),  # another fallback tunnel: no general exemption
    ({"lo": LO, "tunl1": TUNL0}, {}),  # similar name
    ({"lo": LO, "tunl0": TUNL0, "sit0": SIT}, {}),  # an additional interface
    ({"tunl0": TUNL0}, {}),  # no loopback
    ({"lo": LO, "tunl0": dict(TUNL0, link_type=776)}, {}),  # wrong tunnel type
    ({"lo": LO, "tunl0": dict(TUNL0, link_type=None)}, {}),
    ({"lo": LO, "tunl0": dict(TUNL0, up=True)}, {}),
    ({"lo": LO, "tunl0": dict(TUNL0, running=True)}, {}),
    ({"lo": LO, "tunl0": dict(TUNL0, loopback=True)}, {}),
    ({"lo": LO, "tunl0": dict(TUNL0, ipv4_address=True)}, {}),
    ({"lo": LO, "tunl0": {k: v for k, v in TUNL0.items() if k != "ipv4_address"}}, {}),  # unknown address state
    ({"lo": LO, "tunl0": dict(TUNL0, up=0)}, {}),  # malformed: not a boolean
    ({"lo": LO, "tunl0": dict(TUNL0, error="EPERM")}, {}),  # kernel query error
    ({"lo": dict(LO, loopback=False), "tunl0": TUNL0}, {}),  # contradictory loopback metadata
    ({"lo": dict(LO, link_type=768), "tunl0": TUNL0}, {}),
    ({"lo": dict(LO, error="ENODEV"), "tunl0": TUNL0}, {}),
    ({"lo": LO, "tunl0": TUNL0}, {"if_inet6": "fe800000000000000000000000000001 02 40 20 80 tunl0\n"}),
    ({"lo": LO, "tunl0": TUNL0}, {"if_inet6": "not an if_inet6 line\n"}),
    ({"lo": LO, "tunl0": TUNL0}, {"routes": DEFAULT_ROUTE.format(dev="tunl0")}),
    ({"lo": LO, "tunl0": TUNL0}, {"names": ["lo", "tunl0", "tunl0"]}),
    ({"lo": LO, "tunl0": TUNL0}, {"dev": ["lo", "tunl0", "eth0"]}),  # /proc/net/dev disagrees
    ({"lo": LO, "tunl0": TUNL0}, {"dev": "unreadable"}),
], ids=["unknown", "sit0", "tunl1", "extra", "no-lo", "type-776", "type-missing", "up", "running", "loopback-flag",
        "ipv4", "ipv4-unknown", "non-bool", "query-error", "lo-not-loopback", "lo-wrong-type", "lo-error", "ipv6",
        "ipv6-malformed", "route", "duplicate", "dev-mismatch", "dev-unreadable"])
def test_policy_rejects(monkeypatch, interfaces, kw):
    result = isolation_of(monkeypatch, interfaces, **kw)
    assert result["net_fallback_tunnel_inert"] is False and result["net_loopback_only"] is False
    assert result["net_interfaces_safe"] is False and result["network_verified"] is False


def test_policy_interface_query_failure_is_rejected(monkeypatch):
    fake_namespace(monkeypatch, {"lo": LO, "tunl0": TUNL0})

    def broken(name):
        raise OSError(errno.ENODEV, "gone")

    monkeypatch.setattr(worker, "_interface_state", broken)
    result = worker.network_isolation(enter=lambda: True)
    assert result["net_fallback_tunnel_inert"] is False and result["network_verified"] is False
    assert all(result[k] for k in worker.ROUTE_CHECKS)  # the failure stays confined to the check it hit


# --------------------------------------------------------------------- capability state (Phase C7C)


ZERO = "0000000000000000"
STATUS = ("Name:\tpython3\nThreads:\t1\nNoNewPrivs:\t1\n"
          + "".join(f"{k}:\t{ZERO}\n" for k in worker.CAP_SETS))


def test_capability_state_accepts_only_the_fully_dropped_state():
    assert worker.capability_state_ok(STATUS, worker.SECUREBITS) is True
    assert worker.capability_state_ok(STATUS, 0xFF) is True  # extra bits are fine


@pytest.mark.parametrize("status, securebits", [
    *[(STATUS.replace(f"{k}:\t{ZERO}", f"{k}:\t0000000000001000"), worker.SECUREBITS) for k in worker.CAP_SETS],
    (STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), worker.SECUREBITS),
    (STATUS.replace("Threads:\t1", "Threads:\t2"), worker.SECUREBITS),  # other threads keep their capabilities
    (STATUS.replace("CapAmb", "Missing"), worker.SECUREBITS),
    (STATUS.replace(f"CapEff:\t{ZERO}", "CapEff:\tzz"), worker.SECUREBITS),
    (STATUS, worker.SECUREBITS & ~0x02),  # SECBIT_NOROOT not locked
    (STATUS, worker.SECUREBITS & ~0x80),  # ambient raise not locked off
    (STATUS, -1),  # prctl(PR_GET_SECUREBITS) failed
    ("", worker.SECUREBITS),
])
def test_capability_state_rejects(status, securebits):
    assert worker.capability_state_ok(status, securebits) is False


# --------------------------------------------------------------------- strict predicate, one control at a time


# The real worker main() with each control's outcome forced; argv[1] names the one that fails.
FORCED_WORKER = """import sys
import app.worker as w
off = sys.argv[1]
network = dict.fromkeys(("network_namespace", "network_verified", "net_interfaces_safe", *w.ROUTE_CHECKS), True)
network.update(net_loopback_only=True, net_fallback_tunnel_inert=False)
w.network_isolation = lambda: dict(network, **({off: False} if off in network else {}))
w.POSIX = True
w.drop_capabilities = lambda: off != "capabilities_dropped"
def rlimits():
    if off == "rlimits":
        raise OSError("refused")
w._rlimits = rlimits
sys.exit(w.main(["--require-isolation"]))"""
FORCEABLE = [k for k in worker.REQUIRED_CONTROLS if k not in ("process", "audit_hook")]


@pytest.mark.parametrize("off", [None, *FORCEABLE])
def test_strict_mode_never_scans_without_a_required_control(monkeypatch, off):
    cmd = [sys.executable, "-B", "-c", FORCED_WORKER, str(off)]
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=cmd))
    body = post_scan(client, make_pdf()).json()
    if off is None:  # the harness itself scans normally when everything holds
        assert body["verdict"] == Verdict.SAFE and body["complete"] and body["isolation_missing"] == []
    else:
        assert body["verdict"] == Verdict.UNABLE_TO_SCAN and body["findings"] == [] and not body["complete"]
        assert body["isolation_missing"] == [off] and body["isolation"][off] is False
        assert all(s["error"] == f"required isolation unavailable: {off}" for s in body["scanners"])

