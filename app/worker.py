"""Per-scan isolated worker.

Every scan runs all scanners in a fresh child process (`python -m app.worker`), never in
the API process. The parent side (`run`) sends the file on stdin, reads one bounded JSON
report from stdout, enforces a wall-clock timeout and always kills the child's whole
process group. The child side (`main`) applies what containment the platform allows
before it reads a single byte of the document:

  - empty environment (no secrets, no config), cwd = application root, stderr discarded
  - Linux: new user + network namespace, so the process has no network interfaces
    (needs unprivileged user namespaces; usually unavailable inside hosted containers)
  - Linux: rlimits on CPU time, writable memory, file size (0: no file writes), open
    files, core dumps and process/thread creation
  - a Python audit hook that refuses sockets, process creation, native library loading
    and opening files for writing. This is an in-process guard against Python code paths,
    NOT an operating-system boundary: native code is not subject to it

What actually got applied is reported per scan (`isolation`), and with
SECURITY_ENGINE_REQUIRE_ISOLATION=1 the child refuses to analyse anything unless every
control is in place. None of this is a complete sandbox: the child runs as the same
user as the API, inside the same container, and a native-code exploit in a parser can
bypass the audit hook (see docs/malware-research-readiness.md).
"""

import asyncio
import os
import re
import signal
import sys
import traceback
from pathlib import Path
from xml.etree.ElementTree import ParseError as XMLParseError
from zipfile import BadZipFile

from defusedxml.common import DefusedXmlException
from pydantic import ValidationError
from pypdf.errors import PdfReadError

from app.models import ScannerStatus, WorkerReport
from app.scanners.office import OfficeScanError
from app.scanners.pdf import PdfScanError

APP_ROOT = Path(__file__).resolve().parent.parent
POSIX = os.name == "posix"

MAX_INPUT_BYTES = 10 * 1024 * 1024  # mirrors main.MAX_UPLOAD_BYTES
MAX_OUTPUT_BYTES = 1024 * 1024
TIMEOUT_SECONDS = int(os.environ.get("SECURITY_ENGINE_WORKER_TIMEOUT_SECONDS", "30"))
CPU_SECONDS = 20
# Writable private memory per worker (RLIMIT_DATA). Calibrate to the instance: the API itself
# uses ~70 MiB, and MAX_CONCURRENT_SCANS workers can run at once.
MEMORY_MB = int(os.environ.get("SECURITY_ENGINE_WORKER_MEMORY_MB", "320"))
REQUIRE_ISOLATION = os.environ.get("SECURITY_ENGINE_REQUIRE_ISOLATION") == "1"

ISOLATION_CONTROLS = ("process", "network_namespace", "rlimits", "audit_hook")


class WorkerError(RuntimeError):
    """The worker did not produce a usable report. The message is safe to return."""


# ----------------------------------------------------------------------------- parent side


def command() -> list[str]:
    # -E/-s: ignore PYTHON* variables and user site-packages; -B: write no bytecode.
    cmd = [sys.executable, "-B", "-E", "-s", "-m", "app.worker"]
    return cmd + ["--require-isolation"] if REQUIRE_ISOLATION else cmd


def child_env() -> dict[str, str]:
    # Nothing from the API's environment is inherited. Windows (development only) needs
    # SYSTEMROOT for Python to start.
    return {} if POSIX else {"SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows")}


def _kill(proc: asyncio.subprocess.Process) -> None:
    try:
        if POSIX:
            os.killpg(proc.pid, signal.SIGKILL)  # the child leads its own session/group
        elif proc.returncode is None:
            proc.kill()
    except (ProcessLookupError, PermissionError):
        pass


async def _exchange(proc: asyncio.subprocess.Process, data: bytes) -> bytes:
    try:
        proc.stdin.write(data)
        await proc.stdin.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass  # the child exited early; its exit status says why
    finally:
        proc.stdin.close()
    out = bytearray()
    while chunk := await proc.stdout.read(65536):
        out += chunk
        if len(out) > MAX_OUTPUT_BYTES:
            raise WorkerError("scan worker produced too much output")
    await proc.wait()
    return bytes(out)


async def run(data: bytes, cmd: list[str] | None = None, timeout: float | None = None) -> WorkerReport:
    """Scan `data` in a fresh worker process. Raises WorkerError if no valid report comes back."""
    timeout = TIMEOUT_SECONDS if timeout is None else timeout
    proc = await asyncio.create_subprocess_exec(
        *(cmd or command()),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,  # tracebacks may quote attacker-controlled text
        cwd=APP_ROOT,
        env=child_env(),
        start_new_session=POSIX,
    )
    try:
        async with asyncio.timeout(timeout):
            out = await _exchange(proc, data)
    except TimeoutError:
        raise WorkerError(f"scan worker timed out after {timeout:g}s") from None
    finally:
        _kill(proc)  # also reaps anything the child may have started
        # wait() only returns once the pipes close, so discard whatever is left in stdout.
        while await proc.stdout.read(65536):
            pass
        await proc.wait()

    if proc.returncode != 0:
        raise WorkerError(f"scan worker exited abnormally (status {proc.returncode})")
    try:
        return WorkerReport.model_validate_json(out)
    except ValidationError:
        raise WorkerError("scan worker returned an invalid report") from None


# ----------------------------------------------------------------------------- child side

_PATH = re.compile(r"(?:[A-Za-z]:)?(?:[\\/][^\\/\s'\"]+){2,}[\\/]?")


def safe_error(e: BaseException) -> str:
    """Exception text for the authorized client: no control characters, no file system paths."""
    text = _PATH.sub("<path>", f"{type(e).__name__}: {e}")
    text = re.sub(r"[\x00-\x1f\x7f]", "?", text)
    return text[:300]


def classify(error: Exception) -> str:
    """Separate expected rejections of malformed input from possible scanner bugs.

    The PDF/Office scanners wrap low-level failures in their own exception types. A parser
    error, or a scanner's own structure/limit check (no cause), is an expected outcome for
    hostile files; anything else wrapped or raised could be a programming error.
    """
    cause = error.__cause__
    if isinstance(error, (PdfScanError, OfficeScanError)) and cause is None:
        return "invalid_structure"
    if isinstance(error, PdfScanError) and isinstance(cause, PdfReadError):
        return "malformed_input"
    if isinstance(error, OfficeScanError) and isinstance(cause, (BadZipFile, XMLParseError, DefusedXmlException)):
        return "malformed_input"
    return "unexpected"


def code_trace(error: Exception) -> str:
    """Where an unexpected failure happened: file:line:function frames, innermost last.
    Exception messages are left out on purpose; they can quote document content."""
    root = error.__cause__ or error
    frames = traceback.extract_tb(root.__traceback__)[-8:]
    return " < ".join(f"{Path(f.filename).name}:{f.lineno}:{f.name}" for f in reversed(frames))[:1000]


def analyse(scanners, data: bytes, isolation: dict[str, bool] | None = None) -> WorkerReport:
    statuses, findings, traces = [], [], {}
    for scanner in scanners:
        try:
            result = scanner.scan("", data)  # scanners identify formats from content, never names
        except Exception as e:
            kind = classify(e)
            statuses.append(ScannerStatus(name=scanner.name, status="failed", error=safe_error(e), error_kind=kind,
                                          error_type=type(e.__cause__ or e).__name__))
            if kind == "unexpected":
                traces[scanner.name] = re.sub(r"[^A-Za-z0-9_.:<> -]", "?", code_trace(e))
            continue
        if result is None:
            statuses.append(ScannerStatus(name=scanner.name, status="not_applicable"))
        else:
            statuses.append(ScannerStatus(name=scanner.name, status="completed"))
            findings += result
    return WorkerReport(scanners=statuses, findings=findings, isolation=isolation or {}, traces=traces)


def _network_namespace() -> bool:
    # Must run while the process is still single-threaded (unshare(CLONE_NEWUSER) requires it).
    import ctypes

    clone_newuser, clone_newnet = 0x10000000, 0x40000000
    libc = ctypes.CDLL(None, use_errno=True)
    return libc.unshare(clone_newuser | clone_newnet) == 0


def _rlimits() -> None:
    import resource

    for limit, value in [
        (resource.RLIMIT_CPU, (CPU_SECONDS, CPU_SECONDS + 1)),  # SIGXCPU, then SIGKILL
        (resource.RLIMIT_DATA, (MEMORY_MB * 2**20,) * 2),  # MemoryError / abort beyond this
        (resource.RLIMIT_FSIZE, (0, 0)),
        (resource.RLIMIT_CORE, (0, 0)),
        (resource.RLIMIT_NOFILE, (32, 32)),
        (resource.RLIMIT_NPROC, (0, 0)),  # no new processes or threads from here on
    ]:
        resource.setrlimit(limit, value)


BLOCKED_EVENTS = {
    "socket.__new__", "socket.connect", "socket.bind", "socket.sendto", "socket.getaddrinfo",
    "socket.gethostbyname", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.fork", "os.forkpty", "os.kill", "os.killpg", "ctypes.dlopen", "os.remove", "os.rename", "os.rmdir",
    "os.mkdir", "os.chmod", "os.truncate", "webbrowser.open",
}
WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC


def _audit_hook(event: str, args: tuple) -> None:
    if event in BLOCKED_EVENTS:
        raise PermissionError(f"blocked by scan worker policy: {event}")
    if event == "open":
        _, mode, flags = args
        if (isinstance(mode, str) and any(c in mode for c in "wax+")) or (isinstance(flags, int) and flags & WRITE_FLAGS):
            raise PermissionError("blocked by scan worker policy: open for writing")


def main(argv: list[str]) -> int:
    # Rules and parsers load first (trusted files), before any containment that would block them.
    from app.scanners import SCANNERS

    isolation = dict.fromkeys(ISOLATION_CONTROLS, False)
    isolation["process"] = True
    try:
        isolation["network_namespace"] = POSIX and _network_namespace()
    except (OSError, AttributeError):
        pass
    for scanner in SCANNERS:  # warm-up: lets YARA-X start its timeout thread before RLIMIT_NPROC
        try:
            scanner.scan("", b"")
        except Exception:
            pass  # a broken scanner fails again, visibly, on the real input
    try:
        _rlimits()
        isolation["rlimits"] = True
    except (ImportError, ValueError, OSError):
        pass
    sys.addaudithook(_audit_hook)  # cannot be removed once installed
    isolation["audit_hook"] = True

    if "--require-isolation" in argv and not all(isolation.values()):
        missing = ", ".join(k for k, v in isolation.items() if not v)
        statuses = [ScannerStatus(name=s.name, status="failed", error=f"required isolation unavailable: {missing}")
                    for s in SCANNERS]
        report = WorkerReport(scanners=statuses, findings=[], isolation=isolation)
    else:
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            return 3
        report = analyse(SCANNERS, data, isolation)
    sys.stdout.buffer.write(report.model_dump_json().encode())
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
