"""Linux integration tests for the scan worker's operating-system controls.

These run real child processes and check that each rlimit, the process-group kill and the
network namespace actually take effect in the kernel, not only that they were requested.
The rlimit probes deliberately do NOT install the Python audit hook, so they measure the OS
controls alone. Run as a non-root user (root ignores RLIMIT_NPROC), on Python 3.11 like the
production image; see .github/workflows/security-engine-tests.yml. With
FM_REQUIRE_LINUX_TESTS=1 (set in CI) nothing here may skip: a missing platform feature is a
failure, so CI can never report isolation it did not test. All inputs are inert fixtures.
"""

import asyncio
import errno
import functools
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import main, worker
from app.models import Verdict
from tests.office_fixtures import make_ooxml, rels
from tests.pdf_fixtures import make_pdf
from tests.scan_client import post_scan

REQUIRED = os.environ.get("FM_REQUIRE_LINUX_TESTS") == "1"
# Set in CI for a second run with the ipip module loaded, so that every new network namespace
# gets the kernel's tunl0 fallback device, as on the Render staging host.
TUNNEL_EXPECTED = os.environ.get("FM_EXPECT_FALLBACK_TUNNEL") == "1"
pytestmark = pytest.mark.skipif(sys.platform != "linux" and not REQUIRED, reason="Linux-only operating-system controls")

client = TestClient(main.app)


def probe(code: str, timeout: float = 30) -> subprocess.CompletedProcess:
    """Run Python code in a fresh interpreter from the application root."""
    return subprocess.run([sys.executable, "-B", "-c", code], cwd=worker.APP_ROOT, capture_output=True, text=True,
                          timeout=timeout)


def alive(pid: int) -> bool:
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
    except (FileNotFoundError, ProcessLookupError):
        return False
    return state != "Z"  # a zombie has already terminated


def wait_dead(pid: int, seconds: float = 5) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not alive(pid):
            return True
        time.sleep(0.05)
    return False


# --------------------------------------------------------------------- the real worker on Linux


@pytest.mark.parametrize("data, expected", [
    (b"plain text", []),
    (make_pdf(), []),
    (make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>"), ["PDF_LAUNCH_ACTION", "PDF_Launch_Action"]),
    (make_ooxml({"word/_rels/document.xml.rels": rels(("oleObject", "mhtml:https://example.test/x!", True))}),
     ["OFFICE_EXTERNAL_DANGEROUS_SCHEME"]),
])
def test_real_worker_scans_under_rlimits(data, expected):
    # Every scanner must still work with RLIMIT_NPROC=0, RLIMIT_DATA, no file writes and no
    # capabilities in force. In CI the worker runs in strict mode with every control in place.
    report = asyncio.run(worker.run(data, cmd=[*worker.command(), "--require-isolation"] if REQUIRED else None))
    assert report.isolation["process"] and report.isolation["rlimits"] and report.isolation["audit_hook"]
    if REQUIRED:  # CI enables namespaces, so the full worker must actually enter one and verify it
        assert report.isolation["network_namespace"], "worker could not create its network namespace"
        assert report.isolation["network_verified"], {k: report.isolation[k] for k in worker.NETWORK_CHECKS}
        assert report.isolation["capabilities_dropped"], "worker could not drop its capabilities"
        assert worker.missing_controls(report.isolation) == [], report.isolation
        assert report.isolation["net_fallback_tunnel_inert"] is TUNNEL_EXPECTED, report.isolation
    assert all(s.status != "failed" for s in report.scanners), report.scanners
    assert sorted(f.rule_id for f in report.findings) == sorted(expected)


def test_real_worker_through_the_api(monkeypatch):
    monkeypatch.setattr(main, "run_scan", worker.run)
    body = post_scan(client, make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>")).json()
    assert body["verdict"] == Verdict.MALICIOUS and body["complete"] and body["isolation"]["rlimits"]


def test_worker_environment_is_empty():
    report = subprocess.run([sys.executable, "-B", "-E", "-s", "-m", "tests.fake_worker", "env"], input=b"",
                            capture_output=True, cwd=worker.APP_ROOT, env=worker.child_env(), timeout=30)
    # Python itself may set LC_CTYPE when it coerces the C locale to UTF-8.
    assert set(json.loads(report.stdout)) <= {"LC_CTYPE"}


# --------------------------------------------------------------------- each rlimit is enforced by the kernel


LIMITED = "import app.worker as w\nw.CPU_SECONDS = 1\nw.MEMORY_MB = 128\n"


def test_cpu_limit_kills_a_busy_worker():
    start = time.monotonic()
    result = probe(LIMITED + "w._rlimits()\nwhile True: pass")
    assert result.returncode in (-signal.SIGXCPU, -signal.SIGKILL)
    assert time.monotonic() - start < 15


def test_memory_limit_stops_large_allocations():
    result = probe(LIMITED + "w._rlimits()\ntry:\n    b = bytearray(512 * 2**20)\nexcept MemoryError:\n    print('blocked')")
    assert result.stdout.strip() == "blocked", result.stderr


def test_file_writes_are_refused_by_the_kernel(tmp_path):
    target = tmp_path / "written.bin"
    # Unbuffered, so the write(2) itself fails (CPython ignores SIGXFSZ and raises EFBIG).
    result = probe(LIMITED + f"w._rlimits()\ntry:\n    open({str(target)!r}, 'wb', buffering=0).write(b'x')\n"
                             "except OSError as e:\n    print(e.errno)")
    assert result.stdout.strip() == str(errno.EFBIG), result.stderr
    assert not target.exists() or target.stat().st_size == 0


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0 and not REQUIRED,
                    reason="root is exempt from RLIMIT_NPROC")
def test_process_and_thread_creation_are_refused():
    code = LIMITED + """w._rlimits()
import os, threading
out = []
try:
    os.fork()
    out.append('forked')
except OSError as e:
    out.append(str(e.errno))
try:
    threading.Thread(target=lambda: None).start()
    out.append('thread')
except RuntimeError:
    out.append('no-thread')
print(' '.join(out))"""
    assert probe(code).stdout.split() == [str(errno.EAGAIN), "no-thread"]


def test_open_file_limit():
    code = LIMITED + "w._rlimits()\nfs = []\ntry:\n    while True: fs.append(open('/dev/null'))\nexcept OSError as e:\n    print(e.errno, len(fs))"
    err, count = probe(code).stdout.split()
    assert int(err) == errno.EMFILE and int(count) < 32


def test_core_dumps_disabled():
    assert probe(LIMITED + "w._rlimits()\nimport resource\nprint(resource.getrlimit(resource.RLIMIT_CORE))").stdout.strip() == "(0, 0)"


# --------------------------------------------------------------------- network namespace (OS level, no audit hook)


def test_network_namespace_blocks_connections_when_available():
    code = """from app.worker import _network_namespace
import socket
if not _network_namespace():
    print('unavailable')
else:
    try:
        socket.create_connection(('192.0.2.1', 80), timeout=3)  # TEST-NET-1, never routed
        print('connected')
    except OSError as e:
        print('blocked', e.errno)"""
    out = probe(code).stdout.split()
    if out == ["unavailable"]:
        (pytest.fail if REQUIRED else pytest.skip)("unprivileged user/network namespaces are not available on this host")
    assert out == ["blocked", str(errno.ENETUNREACH)]


# --------------------------------------------------------------------- termination and fail-closed behaviour


def fake(mode, *args):
    return [sys.executable, "-B", "-m", "tests.fake_worker", mode, *args]


@pytest.mark.parametrize("mode", ["spawn-sleep", "spawn-exit"])
def test_process_group_is_killed_including_grandchildren(mode, tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    with pytest.raises(worker.WorkerError):
        asyncio.run(worker.run(b"x", cmd=fake(mode, str(pid_file)), timeout=2))
    assert wait_dead(int(pid_file.read_text())), "grandchild process survived the worker"


def test_native_crash_fails_closed(monkeypatch):
    with pytest.raises(worker.WorkerError, match=f"status {-signal.SIGSEGV}"):
        asyncio.run(worker.run(b"x", cmd=fake("segv")))
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=fake("segv")))
    body = post_scan(client, b"x").json()
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and not body["complete"]
    assert client.get("/health").status_code == 200


def test_timeout_leaves_no_worker_behind(tmp_path):
    pid_file = tmp_path / "grandchild.pid"
    start = time.monotonic()
    with pytest.raises(worker.WorkerError, match="timed out"):
        asyncio.run(worker.run(b"x", cmd=fake("spawn-sleep", str(pid_file)), timeout=1))
    assert time.monotonic() - start < 5
    assert wait_dead(int(pid_file.read_text()))


# --------------------------------------------------------------------- network isolation verification (Phase C5)


NET_PROBE = """import json
from app.worker import _network_namespace, verify_network_isolation
entered = {enter}
if entered and not _network_namespace():
    print(json.dumps("unavailable"))
else:
    print(json.dumps(verify_network_isolation()))"""


def test_network_verification_passes_inside_the_namespace():
    out = json.loads(probe(NET_PROBE.format(enter=True)).stdout)
    if out == "unavailable":
        (pytest.fail if REQUIRED else pytest.skip)("unprivileged user/network namespaces are not available on this host")
    assert all(out[k] for k in worker.ROUTE_CHECKS), out
    assert out["net_loopback_only"] != out["net_fallback_tunnel_inert"], out  # exactly one safe interface state
    if TUNNEL_EXPECTED:
        assert out["net_fallback_tunnel_inert"] is True and out["net_loopback_only"] is False, out


def test_network_verification_detects_the_host_network():
    # The runner's own namespace has real interfaces and routes, so the same checks must fail.
    # Only route lookups against a documentation address are made: no packet is sent.
    out = json.loads(probe(NET_PROBE.format(enter=False)).stdout)
    assert not out["net_loopback_only"] and not out["net_ipv4_no_route"], out
    assert not out["net_fallback_tunnel_inert"], out
    assert not all(out.values())


# --------------------------------------------------------------------- strict mode fails closed on failed verification


# The real worker module in a fresh interpreter; only verify_network_isolation is replaced, in
# that process alone. The namespace itself is really entered on hosts that allow it.
FAULTY_WORKER = """import os, sys
import app.worker as w
mode = sys.argv[1]
# Really enter the namespace where the host allows it; elsewhere simulate entry so the
# verification path (the subject of these tests) is still reached.
real_enter = w._network_namespace
w.POSIX = True
w._network_namespace = lambda: (os.name == "posix" and real_enter()) or True
def faulty():
    if mode == "raise":
        raise RuntimeError("injected verification fault")
    checks = dict.fromkeys(w.NETWORK_CHECKS, True)
    checks["net_ipv4_unreachable"] = False
    return checks
def no_capabilities():
    if mode == "caps-raise":
        raise PermissionError("injected capability fault")
    return False
if mode in ("fail", "raise"):
    w.verify_network_isolation = faulty
else:
    w.drop_capabilities = no_capabilities
sys.exit(w.main(["--require-isolation"]))"""


def faulty_worker(mode):
    return [sys.executable, "-B", "-c", FAULTY_WORKER, mode]


def test_strict_mode_refuses_to_scan_when_network_verification_fails(monkeypatch):
    report = asyncio.run(worker.run(make_pdf(), cmd=faulty_worker("fail")))
    assert report.findings == []
    assert all(s.status == "failed" and "required isolation unavailable" in s.error for s in report.scanners)
    assert report.isolation["network_verified"] is False and report.isolation["net_ipv4_unreachable"] is False
    missing = report.scanners[0].error
    assert "network_verified" in missing and "net_ipv4_unreachable" in missing
    if REQUIRED:  # namespace really entered, so verification alone caused the refusal
        assert report.isolation["network_namespace"] is True and "network_namespace" not in missing

    # Through the API: never SAFE, reported as incomplete with the reason.
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=faulty_worker("fail")))
    body = post_scan(client, make_pdf()).json()
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and body["findings"] == [] and not body["complete"]
    assert all("required isolation unavailable" in s["error"] and "network_verified" in s["error"] for s in body["scanners"])


def test_strict_mode_fails_closed_when_verification_crashes(monkeypatch):
    with pytest.raises(worker.WorkerError, match="exited abnormally"):
        asyncio.run(worker.run(make_pdf(), cmd=faulty_worker("raise")))
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=faulty_worker("raise")))
    body = post_scan(client, make_pdf()).json()
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and body["findings"] == [] and not body["complete"]
    assert all(s["status"] == "failed" and s["error_kind"] == "worker" for s in body["scanners"])


# --------------------------------------------------------------------- network diagnostics (Phase C7B)


DIAG_PROBE = """import json
from app.worker import _network_namespace, collect_diagnostics
entered = {enter}
if entered and not _network_namespace():
    print(json.dumps("unavailable"))
else:
    print(collect_diagnostics().model_dump_json())"""


def test_diagnostics_inside_the_namespace_show_only_expected_interfaces():
    out = json.loads(probe(DIAG_PROBE.format(enter=True)).stdout)
    if out == "unavailable":
        (pytest.fail if REQUIRED else pytest.skip)("unprivileged user/network namespaces are not available on this host")
    assert out["collection_error"] is None and out["enumeration_error"] is None and out["proc_error"] is None
    names = [i["name"] for i in out["interfaces"]]
    assert names == ["lo", "tunl0"] if TUNNEL_EXPECTED else names == ["lo"], out
    lo = out["interfaces"][0]
    assert lo["loopback"] is True and lo["link_type"] == 772 and lo["error"] is None  # ARPHRD_LOOPBACK
    assert out["usable_routes_v4"] == 0 and out["usable_routes_v6"] == 0
    if TUNNEL_EXPECTED:  # the kernel's own fallback device, in the state observed on Render
        tun = out["interfaces"][1]
        assert (tun["link_type"], tun["up"], tun["running"], tun["ipv4_address"], tun["ipv6_addresses"]) == \
            (768, False, False, False, 0), out


def test_diagnostics_read_real_interface_state_in_the_host_namespace():
    # The runner's own interfaces exercise the ioctl parsing on real data; nothing is sent.
    out = json.loads(probe(DIAG_PROBE.format(enter=False)).stdout)
    assert out["collection_error"] is None and out["usable_routes_v4"] >= 1, out
    assert any(i["loopback"] and i["link_type"] == 772 for i in out["interfaces"]), out
    assert any(i["up"] and i["ipv4_address"] and not i["loopback"] and i["usable_routes_v4"] >= 1
               for i in out["interfaces"]), out


def test_real_worker_returns_diagnostics_only_when_asked():
    cmd = worker.command()
    assert asyncio.run(worker.run(make_pdf(), cmd=cmd)).diagnostics is None
    report = asyncio.run(worker.run(make_pdf(), cmd=cmd + ["--net-diagnostics"]))
    assert report.diagnostics is not None and report.diagnostics.collection_error is None
    assert ([i.name for i in report.diagnostics.interfaces] == ["lo"]) == report.isolation["net_loopback_only"]


# --------------------------------------------------------------------- strict mode without dropped capabilities


@pytest.mark.parametrize("mode", ["caps-fail", "caps-raise"])
def test_strict_mode_refuses_to_scan_without_dropped_capabilities(monkeypatch, mode):
    report = asyncio.run(worker.run(make_pdf(), cmd=faulty_worker(mode)))
    assert report.findings == [] and report.isolation["capabilities_dropped"] is False
    assert all(s.status == "failed" and "capabilities_dropped" in s.error for s in report.scanners)
    if REQUIRED:  # everything else is really in place, so the capabilities alone caused the refusal
        assert worker.missing_controls(report.isolation) == ["capabilities_dropped"], report.isolation

    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=faulty_worker(mode)))
    body = post_scan(client, make_pdf()).json()
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and body["findings"] == [] and not body["complete"]
    assert "capabilities_dropped" in body["isolation_missing"]


# --------------------------------------------------------------------- capabilities, checked in the kernel (Phase C7C)


# Runs in its own throwaway user + network namespace, never the runner's: it brings that
# namespace's lo up once (proving CAP_NET_ADMIN was really held), drops everything the way the
# worker does, then tries every way back.
CAP_PROBE = r"""import ctypes, errno, fcntl, json, socket, struct, subprocess, sys
import app.worker as w
if not w._network_namespace():
    print(json.dumps("unavailable")); sys.exit()
libc = ctypes.CDLL(None, use_errno=True)
def err(ok):
    return "ok" if ok else errno.errorcode.get(ctypes.get_errno(), "unknown")
def set_lo_flags(flags):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            fcntl.ioctl(s, 0x8914, struct.pack("16sh22x", b"lo", flags))  # SIOCSIFFLAGS
            return "ok"
        except OSError as e:
            return errno.errorcode[e.errno]
def status(text):
    return {k: v.strip() for k, v in (l.split(":", 1) for l in text.splitlines() if l.startswith(("Cap", "NoNewPrivs")))}
out = {"lo_up_before": set_lo_flags(w.IFF_UP)}
out["dropped"] = w.drop_capabilities()
out["status"] = status(open("/proc/self/status").read())
out["securebits"] = libc.prctl(w.PR_GET_SECUREBITS, 0, 0, 0, 0)
out["lo_down_after"] = set_lo_flags(0)
net_admin = 1 << 12  # CAP_NET_ADMIN
header = (ctypes.c_uint32 * 2)(w.LINUX_CAPABILITY_VERSION_3, 0)
out["capset"] = err(libc.capset(header, (ctypes.c_uint32 * 6)(net_admin, net_admin, net_admin, 0, 0, 0)) == 0)
out["ambient_raise"] = err(libc.prctl(w.PR_CAP_AMBIENT, 2, 12, 0, 0) == 0)  # PR_CAP_AMBIENT_RAISE
out["bounding_has_net_admin"] = libc.prctl(23, 12, 0, 0, 0)  # PR_CAPBSET_READ
out["securebits_unlock"] = err(libc.prctl(w.PR_SET_SECUREBITS, 0, 0, 0, 0) == 0)
out["setuid_root"] = err(libc.setuid(0) == 0)
child = subprocess.run([sys.executable, "-c", "print(open('/proc/self/status').read())"], capture_output=True, text=True)
out["exec_status"] = status(child.stdout)
# A nested user namespace grants capabilities only over namespaces it owns, not this one.
out["nested_userns"] = err(libc.unshare(0x10000000) == 0)
out["lo_down_nested"] = set_lo_flags(0)
print(json.dumps(out))"""


def test_capabilities_are_dropped_in_the_kernel_and_cannot_be_regained():
    out = json.loads(probe(CAP_PROBE).stdout)
    if out == "unavailable":
        (pytest.fail if REQUIRED else pytest.skip)("unprivileged user/network namespaces are not available on this host")
    assert out["lo_up_before"] == "ok", out  # CAP_NET_ADMIN was really held before the drop
    assert out["dropped"] is True, out
    assert {k: int(out["status"][k], 16) for k in worker.CAP_SETS} == dict.fromkeys(worker.CAP_SETS, 0), out
    assert out["status"]["NoNewPrivs"] == "1" and out["securebits"] & worker.SECUREBITS == worker.SECUREBITS, out
    assert out["lo_down_after"] == "EPERM", out  # the namespace can no longer be reconfigured
    assert out["capset"] == "EPERM" and out["ambient_raise"] == "EPERM", out
    assert out["bounding_has_net_admin"] == 0, out
    assert out["securebits_unlock"] == "EPERM", out
    # The worker's user namespace maps no IDs at all, so any setuid() is invalid before
    # capabilities are even considered: no UID change is possible.
    assert out["setuid_root"] == "EINVAL", out
    assert all(int(out["exec_status"][k], 16) == 0 for k in worker.CAP_SETS), out  # exec adds nothing
    assert out["exec_status"]["NoNewPrivs"] == "1", out
    assert out["lo_down_nested"] == "EPERM", out  # with or without a nested user namespace

