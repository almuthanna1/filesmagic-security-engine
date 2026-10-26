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

from app import auth, main, worker
from app.models import Verdict
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
    if all(report.isolation.values()):
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


ALL_PASS = dict.fromkeys(worker.NETWORK_CHECKS, True)


def test_network_isolation_without_namespace_reports_everything_missing():
    def must_not_run():
        raise AssertionError("verification must not run outside a namespace")

    for enter in (lambda: False, lambda: (_ for _ in ()).throw(OSError("unshare denied"))):
        result = worker.network_isolation(enter=enter, verify=must_not_run)
        assert result == {"network_namespace": False, "network_verified": False, **dict.fromkeys(worker.NETWORK_CHECKS, False)}


def test_network_isolation_with_verified_namespace():
    result = worker.network_isolation(enter=lambda: True, verify=lambda: dict(ALL_PASS))
    assert result["network_namespace"] and result["network_verified"]
    assert all(result[k] for k in worker.NETWORK_CHECKS)


@pytest.mark.parametrize("failed", worker.NETWORK_CHECKS)
def test_network_isolation_one_failed_check_is_not_verified(failed):
    checks = dict(ALL_PASS, **{failed: False})
    result = worker.network_isolation(enter=lambda: True, verify=lambda: checks)
    assert result["network_namespace"] is True and result["network_verified"] is False
    assert result[failed] is False and sum(not result[k] for k in worker.NETWORK_CHECKS) == 1


def test_network_isolation_only_literal_true_counts():
    # Missing or non-boolean check values are failures, never passes.
    result = worker.network_isolation(enter=lambda: True, verify=lambda: {"net_loopback_only": 1})
    assert result["network_verified"] is False and not any(result[k] for k in worker.NETWORK_CHECKS)


def test_real_worker_network_report_is_consistent():
    # Holds on every host: verified exactly when all checks pass, and no check passes without a namespace.
    iso = asyncio.run(worker.run(DATA)).isolation
    assert iso["network_verified"] == all(iso[k] for k in worker.NETWORK_CHECKS)
    if not iso["network_namespace"]:
        assert not iso["network_verified"] and not any(iso[k] for k in worker.NETWORK_CHECKS)


def test_scan_result_reports_configured_strict_mode(monkeypatch):
    assert post_scan(client, DATA).json()["isolation_required"] is False
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    assert post_scan(client, DATA).json()["isolation_required"] is True
