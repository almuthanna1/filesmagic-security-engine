"""Per-scan isolated worker.

Every scan runs all scanners in a fresh child process (`python -m app.worker`), never in
the API process. The parent side (`run`) sends the file on stdin, reads one bounded JSON
report from stdout, enforces a wall-clock timeout and always kills the child's whole
process group. The child side (`main`) applies what containment the platform allows
before it reads a single byte of the document:

  - empty environment (no secrets, no config), cwd = application root, stderr discarded
  - Linux: new user + network namespace, so the process has no usable network interface
    (needs unprivileged user namespaces: available on the Render staging host, not inside
    Docker's default seccomp profile). Inside it, the worker independently verifies through
    OS interfaces that no outbound route exists (`verify_network_isolation`), without sending
    any traffic. The only interface accepted besides `lo` is the kernel's inert IP-in-IP
    fallback device `tunl0` (`fallback_tunnel_inert`)
  - Linux: then every capability is dropped for good (`drop_capabilities`), so the worker can
    no longer reconfigure its namespace's interfaces or routes, and exec cannot add privileges
  - Linux: rlimits on CPU time, writable memory, file size (0: no file writes), open
    files, core dumps and process/thread creation
  - a Python audit hook that refuses sockets, process creation, native library loading
    and opening files for writing. This is an in-process guard against Python code paths,
    NOT an operating-system boundary: native code is not subject to it

With SECURITY_ENGINE_NET_DIAGNOSTICS=1 (staging only) the worker also describes what its
network namespace contains (`network_diagnostics`); the API logs that and never returns it.

What actually got applied is reported per scan (`isolation`), and with
SECURITY_ENGINE_REQUIRE_ISOLATION=1 the child refuses to analyse anything unless every
control is in place. None of this is a complete sandbox: the child runs as the same
user as the API, inside the same container, and a native-code exploit in a parser can
bypass the audit hook (see docs/malware-research-readiness.md).
"""

import asyncio
import errno
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

from app.models import NetworkDiagnostics, ScannerStatus, WorkerReport
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
NET_DIAGNOSTICS = os.environ.get("SECURITY_ENGINE_NET_DIAGNOSTICS") == "1"

# Reported per scan. network_namespace: unshare() succeeded. Inside it, INTERFACE_CHECKS say
# literally which state was found: only loopback, or loopback plus the kernel's inert IP-in-IP
# fallback device (Render, docs/malware-research-readiness.md s. 13). net_interfaces_safe: exactly
# one of the two holds. network_verified: net_interfaces_safe and every ROUTE_CHECKS check.
INTERFACE_CHECKS = ("net_loopback_only", "net_fallback_tunnel_inert")
ROUTE_CHECKS = ("net_ipv4_no_route", "net_ipv6_no_route", "net_ipv4_unreachable", "net_ipv6_unreachable")
NETWORK_CHECKS = (*INTERFACE_CHECKS, *ROUTE_CHECKS)
ISOLATION_CONTROLS = ("process", "network_namespace", "network_verified", "net_interfaces_safe", *NETWORK_CHECKS,
                      "capabilities_dropped", "rlimits", "audit_hook")
# With --require-isolation every one of these must be true. INTERFACE_CHECKS are reported as found
# (one of them is false by design) and are required through net_interfaces_safe.
REQUIRED_CONTROLS = tuple(k for k in ISOLATION_CONTROLS if k not in INTERFACE_CHECKS)
# Documentation-only addresses (RFC 5737, RFC 3849): never routed on the internet.
TEST_NET_V4 = ("192.0.2.1", 9)
TEST_NET_V6 = ("2001:db8::1", 9)
RTF_UP, RTF_REJECT = 0x0001, 0x0200
SIOCGIFFLAGS, SIOCGIFADDR, SIOCGIFHWADDR = 0x8913, 0x8915, 0x8927
IFF_UP, IFF_LOOPBACK, IFF_RUNNING = 0x1, 0x8, 0x40
ARPHRD_TUNNEL, ARPHRD_LOOPBACK = 768, 772
# Created by the kernel in every new network namespace while the host has the ipip module loaded
# (unless net.core.fb_tunnels_only_for_init_net is set); it cannot be deleted from inside.
FALLBACK_TUNNEL = "tunl0"
PR_CAPBSET_DROP, PR_GET_SECUREBITS, PR_SET_SECUREBITS = 24, 27, 28
PR_SET_NO_NEW_PRIVS, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 38, 47, 4
# SECBIT_NOROOT, SECBIT_NO_SETUID_FIXUP and SECBIT_NO_CAP_AMBIENT_RAISE, each locked, and
# SECBIT_KEEP_CAPS locked off: no capabilities from root, setuid() or the ambient set, ever.
SECUREBITS = 0x01 | 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
LINUX_CAPABILITY_VERSION_3 = 0x20080522
CAP_SETS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
MAX_DIAG_INTERFACES = 16


class WorkerError(RuntimeError):
    """The worker did not produce a usable report. The message is safe to return."""


# ----------------------------------------------------------------------------- parent side


def command() -> list[str]:
    # -E/-s: ignore PYTHON* variables and user site-packages; -B: write no bytecode.
    cmd = [sys.executable, "-B", "-E", "-s", "-m", "app.worker"]
    return cmd + ["--require-isolation"] * REQUIRE_ISOLATION + ["--net-diagnostics"] * NET_DIAGNOSTICS


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


def usable_route_devices(text: str, flags_col: int, dev_col: int, header: bool) -> list[str]:
    """Devices of the routes in /proc/net/route or /proc/net/ipv6_route text that could carry
    traffic out: up, not a reject/unreachable entry, and not on the loopback device."""
    devices = []
    for line in text.splitlines()[1 if header else 0:]:
        fields = line.split()
        if len(fields) <= max(flags_col, dev_col):
            continue
        flags = int(fields[flags_col], 16)
        if flags & RTF_UP and not flags & RTF_REJECT and fields[dev_col] != "lo":
            devices.append(fields[dev_col])
    return devices


def usable_routes(text: str, flags_col: int, dev_col: int, header: bool) -> int:
    return len(usable_route_devices(text, flags_col, dev_col, header))


def _read(path: str, missing_ok: bool = False) -> str:
    try:
        return Path(path).read_text()
    except FileNotFoundError:
        if missing_ok:  # IPv6 disabled in the kernel: there is no IPv6 routing table at all
            return ""
        raise  # a missing IPv4 table is unexpected: fail closed


def _route_lookup_fails(family: int, address: tuple) -> bool:
    """UDP connect() only selects a route and a source address; it never sends a datagram."""
    import errno
    import socket

    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
    except OSError as e:
        return family == socket.AF_INET6 and e.errno == errno.EAFNOSUPPORT  # IPv6 not available at all
    with sock:
        try:
            sock.connect(address)
        except OSError as e:
            return e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL)
    return False


def missing_controls(isolation: dict) -> list[str]:
    """Required controls that are not literally true. Strict mode scans only if this is empty."""
    return [k for k in REQUIRED_CONTROLS if isolation.get(k) is not True]


def fallback_tunnel_inert(names: list) -> bool:
    """True only for exactly lo + tunl0, where tunl0 is the kernel's IP-in-IP fallback device and
    unusable: link type ARPHRD_TUNNEL, down, not running, no IPv4 or IPv6 address and no usable
    route, lo is a real loopback device, and /proc/net/dev lists the same two interfaces. Any
    other interface, a missing, malformed or contradictory value, or a query error is False."""
    if sorted(names) != ["lo", FALLBACK_TUNNEL]:
        return False
    dev = [line.split(":", 1)[0].strip() for line in _read("/proc/net/dev").splitlines()[2:]]
    if sorted(dev) != ["lo", FALLBACK_TUNNEL]:
        return False
    addr6 = [line.split() for line in _read("/proc/net/if_inet6", missing_ok=True).splitlines() if line.strip()]
    if any(len(f) != 6 for f in addr6):
        return False
    routes = (usable_route_devices(_read("/proc/net/route"), 3, 0, header=True)
              + usable_route_devices(_read("/proc/net/ipv6_route", missing_ok=True), 8, 9, header=False))
    lo, tun = _interface_state("lo"), _interface_state(FALLBACK_TUNNEL)
    return ("error" not in lo and lo.get("loopback") is True and lo.get("link_type") == ARPHRD_LOOPBACK
            and "error" not in tun and tun.get("link_type") == ARPHRD_TUNNEL
            and all(tun.get(k) is False for k in ("up", "running", "loopback", "ipv4_address"))
            and FALLBACK_TUNNEL not in (f[5] for f in addr6) and FALLBACK_TUNNEL not in routes)


def verify_network_isolation() -> dict[str, bool]:
    """Independent check, from inside the namespace, that there is no usable outbound route.
    /proc/net/*, the interface list and SIOCGIF* ioctls describe the calling process's network
    namespace. No DNS lookups and no packets: only route lookups against documentation addresses."""
    import socket

    checks = dict.fromkeys(NETWORK_CHECKS, False)
    names = None
    try:
        names = [name for _, name in socket.if_nameindex()]
        checks["net_loopback_only"] = set(names) <= {"lo"}
        checks["net_ipv4_no_route"] = usable_routes(_read("/proc/net/route"), 3, 0, header=True) == 0
        checks["net_ipv6_no_route"] = usable_routes(_read("/proc/net/ipv6_route", missing_ok=True), 8, 9,
                                                    header=False) == 0
        checks["net_ipv4_unreachable"] = _route_lookup_fails(socket.AF_INET, TEST_NET_V4)
        checks["net_ipv6_unreachable"] = _route_lookup_fails(socket.AF_INET6, TEST_NET_V6)
    except (OSError, ValueError):
        pass  # anything unexpected leaves the remaining checks false: fail closed
    if names is not None:
        try:
            checks["net_fallback_tunnel_inert"] = fallback_tunnel_inert(names)
        except (OSError, ValueError, TypeError):
            pass
    return checks


def _errno_name(e: OSError) -> str:
    return errno.errorcode.get(e.errno, "unknown") if isinstance(e.errno, int) else "none"


def _interface_state(name: str) -> dict:
    """Flags, link type and whether an IPv4 address is set, via SIOCGIF* ioctls on an AF_INET
    socket: like /proc/net, these describe the calling process's network namespace (/sys does not)."""
    import fcntl
    import socket
    import struct

    req = struct.pack("16s24x", os.fsencode(name)[:15])
    state = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            flags = struct.unpack_from("H", fcntl.ioctl(s, SIOCGIFFLAGS, req), 16)[0]
            state.update(up=bool(flags & IFF_UP), running=bool(flags & IFF_RUNNING),
                         loopback=bool(flags & IFF_LOOPBACK))
            state["link_type"] = struct.unpack_from("H", fcntl.ioctl(s, SIOCGIFHWADDR, req), 16)[0]  # ARPHRD_*
            fcntl.ioctl(s, SIOCGIFADDR, req)
            state["ipv4_address"] = True
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL and "link_type" in state:
                state["ipv4_address"] = False
            else:
                state["error"] = _errno_name(e)
    return state


def network_diagnostics() -> dict:
    """Staging-only evidence for the network checks: what the worker's namespace contains.
    Flags, counts and kernel error names only (no addresses); interface names sanitised; at
    most MAX_DIAG_INTERFACES entries. Purely descriptive: never feeds the isolation result."""
    import socket
    from collections import Counter

    diag = {}
    try:
        pairs = list(socket.if_nameindex())
    except OSError as e:
        diag.update(enumeration_error=type(e).__name__, enumeration_errno=_errno_name(e))
        pairs = []
    diag["interface_count"] = len(pairs)
    routes, addr6 = {}, Counter()
    try:
        routes["v4"] = usable_route_devices(_read("/proc/net/route"), 3, 0, header=True)
        routes["v6"] = usable_route_devices(_read("/proc/net/ipv6_route", missing_ok=True), 8, 9, header=False)
        addr6.update(f[5] for f in map(str.split, _read("/proc/net/if_inet6", missing_ok=True).splitlines())
                     if len(f) == 6)
    except (OSError, ValueError) as e:
        diag["proc_error"] = type(e).__name__
    diag.update({f"usable_routes_{v}": len(routes[v]) for v in routes})
    interfaces = []
    for index, name in pairs[:MAX_DIAG_INTERFACES]:
        entry = {"index": index if isinstance(index, int) and 0 <= index < 2**31 else -1,
                 "name": re.sub(r"[^A-Za-z0-9_.:@-]", "?", str(name))[:15] or "?",
                 "ipv6_addresses": addr6[name],
                 **{f"usable_routes_{v}": routes[v].count(name) for v in routes}}
        try:
            entry.update(_interface_state(str(name)))
        except (OSError, ValueError, TypeError) as e:
            entry["error"] = type(e).__name__
        interfaces.append(entry)
    diag["interfaces"] = interfaces
    return diag


def collect_diagnostics(collect=None) -> NetworkDiagnostics:
    """network_diagnostics() that can never break a scan: any fault becomes collection_error."""
    try:
        return NetworkDiagnostics.model_validate((collect or network_diagnostics)())
    except Exception as e:
        return NetworkDiagnostics(collection_error=type(e).__name__[:40])


def network_isolation(enter=None, verify=None) -> dict[str, bool]:
    """Enter a new network namespace and verify it. Returns network_namespace (entered),
    net_interfaces_safe, network_verified and the checks themselves; anything not established
    is False. enter/verify are injectable for tests only."""
    enter = enter or (lambda: POSIX and _network_namespace())
    verify = verify or verify_network_isolation
    result = {"network_namespace": False, "network_verified": False, "net_interfaces_safe": False,
              **dict.fromkeys(NETWORK_CHECKS, False)}
    try:
        result["network_namespace"] = bool(enter())
    except (OSError, AttributeError):
        return result
    if result["network_namespace"]:
        checks = verify()
        result.update({k: checks.get(k) is True for k in NETWORK_CHECKS})
        # Exactly one interface state: both at once is contradictory, so it fails.
        result["net_interfaces_safe"] = result["net_loopback_only"] != result["net_fallback_tunnel_inert"]
        result["network_verified"] = result["net_interfaces_safe"] and all(result[k] for k in ROUTE_CHECKS)
    return result


def capability_state_ok(status: str, securebits: int) -> bool:
    """/proc/self/status of a single-threaded process holding no capability in any set, with
    no_new_privs set, and the SECUREBITS locks in place. Missing or malformed values are False."""
    try:
        fields = {k: v.strip() for k, v in (line.split(":", 1) for line in status.splitlines() if ":" in line)}
        return (all(int(fields[k], 16) == 0 for k in CAP_SETS) and fields["NoNewPrivs"] == "1"
                and fields["Threads"] == "1" and securebits >= 0 and securebits & SECUREBITS == SECUREBITS)
    except (KeyError, ValueError):
        return False


def drop_capabilities() -> bool:
    """Give up every capability for good. In its user namespace the worker holds all of them,
    including CAP_NET_ADMIN over its network namespace; afterwards it cannot change interfaces or
    routes, regain a capability through capset(), the ambient or bounding set, setuid() or exec.
    Securebits and the bounding set need CAP_SETPCAP, so they come before capset() empties the
    rest. Capabilities are per thread: this must run while the worker is single-threaded, so
    every later thread inherits the empty sets. True only if the kernel reports that state."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)

    def prctl(option: int, arg: int = 0) -> int:
        return libc.prctl(option, ctypes.c_ulong(arg), ctypes.c_ulong(0), ctypes.c_ulong(0), ctypes.c_ulong(0))

    prctl(PR_SET_NO_NEW_PRIVS, 1)  # exec can never add privileges (setuid bits, file capabilities)
    prctl(PR_SET_SECUREBITS, SECUREBITS)
    for cap in range(64):  # numbers above the kernel's last capability fail harmlessly
        prctl(PR_CAPBSET_DROP, cap)
    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)
    header = (ctypes.c_uint32 * 2)(LINUX_CAPABILITY_VERSION_3, 0)
    libc.capset(header, (ctypes.c_uint32 * 6)())  # effective, permitted, inheritable: all empty
    return capability_state_ok(Path("/proc/self/status").read_text(), prctl(PR_GET_SECUREBITS))


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
    isolation.update(network_isolation())  # before the audit hook, which forbids sockets
    # Inside the namespace only: outside it, this would describe the host's network.
    diagnostics = collect_diagnostics() if "--net-diagnostics" in argv and isolation["network_namespace"] else None
    try:  # still single-threaded here, and before the audit hook, which forbids ctypes
        isolation["capabilities_dropped"] = POSIX and drop_capabilities()
    except (OSError, AttributeError, TypeError):  # no prctl/capset here: stays False
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

    if "--require-isolation" in argv and (missing := ", ".join(missing_controls(isolation))):
        statuses = [ScannerStatus(name=s.name, status="failed", error=f"required isolation unavailable: {missing}")
                    for s in SCANNERS]
        report = WorkerReport(scanners=statuses, findings=[], isolation=isolation)
    else:
        data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(data) > MAX_INPUT_BYTES:
            return 3
        report = analyse(SCANNERS, data, isolation)
    report.diagnostics = diagnostics
    sys.stdout.buffer.write(report.model_dump_json().encode())
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
