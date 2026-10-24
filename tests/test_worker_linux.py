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
    # Every scanner must still work with RLIMIT_NPROC=0, RLIMIT_DATA and no file writes in force.
    report = asyncio.run(worker.run(data))
    assert report.isolation["process"] and report.isolation["rlimits"] and report.isolation["audit_hook"]
    if REQUIRED:  # CI enables namespaces, so the full worker must actually enter one
        assert report.isolation["network_namespace"], "worker could not create its network namespace"
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
