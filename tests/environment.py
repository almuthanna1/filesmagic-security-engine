"""Environment facts the Linux tests depend on, each measured directly, never assumed or set by a
variable. A test skips for an unsupported environment only through unsupported(), and only after
the condition was demonstrated here; with FM_REQUIRE_LINUX_TESTS=1 (CI) the same call fails, so
CI can never skip what it is meant to test. Every reason starts with UNSUPPORTED, so the run's log
(pytest -rs) and JUnit XML list each such skip with its test. docs/offline-vm-validation-phase6.md,
Section 5.5."""

import os
import subprocess
from pathlib import Path

import pytest

REQUIRED = os.environ.get("FM_REQUIRE_LINUX_TESTS") == "1"
UNSUPPORTED = "unsupported environment (demonstrated): "


def unsupported(reason: str) -> None:
    (pytest.fail if REQUIRED else pytest.skip)(UNSUPPORTED + reason)


def apparmor_label() -> str | None:
    """This process's AppArmor label, e.g. 'filesmagic-eval-python (enforce)'; None if unreadable."""
    for path in ("/proc/self/attr/apparmor/current", "/proc/self/attr/current"):
        try:
            return Path(path).read_text().strip().rstrip("\x00")
        except OSError:
            continue
    return None


def enforced_profile() -> str | None:
    """The label if an AppArmor profile is enforced on this process (complain mode does not count)."""
    label = apparmor_label()
    return label if label and label.endswith("(enforce)") else None


def exec_denied(program: str = "bash") -> str | None:
    """Why `program` cannot be started here, if the reason is an enforced AppArmor profile: the
    profile is enforced *and* starting it raises PermissionError. Anything else is None (so the
    test runs, and fails if it must)."""
    label = enforced_profile()
    if not label:
        return None
    try:
        subprocess.run([program, "-c", "true"], capture_output=True, timeout=10)
    except PermissionError:
        return f"confined as {label!r}, which denies starting {program} (intended)"
    return None


def offline_host(net: Path = Path("/proc/self/net")) -> str | None:
    """A description of this network namespace if it is shown to have only the loopback interface
    and no non-loopback IPv4 or IPv6 route, read from /proc/self/net (no socket, and not the
    worker's own checks). None if any of it cannot be read or does not hold."""
    try:
        interfaces = [line.split(":", 1)[0].strip() for line in (net / "dev").read_text().splitlines()[2:]]
        v4 = [line.split()[0] for line in (net / "route").read_text().splitlines()[1:] if line.strip()]
        v6 = [line.split()[-1] for line in (net / "ipv6_route").read_text().splitlines() if line.strip()]
    except (OSError, IndexError):
        return None
    if interfaces == ["lo"] and all(d == "lo" for d in v4 + v6):
        return f"offline host: interfaces {interfaces}, IPv4 routes {len(v4)}, IPv6 routes all on lo ({len(v6)})"
    return None
