"""Linux-only regression: real, legitimate system binaries must not be false positives.

The static scanner reads bytes; it never executes a binary. Real executables are expected to be
SUSPICIOUS (the reference Native_Executable rule marks every native executable), which is correct,
not a false positive. The false positive this guards against is MALICIOUS: no benign system binary
may trip the engine's ELF malware signatures. With FM_REQUIRE_LINUX_TESTS=1 (CI) the test fails
rather than skips when too few binaries are found, so CI cannot pass by testing nothing.
"""

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="reads real Linux ELF binaries")

MAGIC = b"\x7fELF"
MAX = 8 * 1024 * 1024  # skip very large binaries to keep the run fast


def _binaries(limit: int = 40) -> list[Path]:
    seen, out = set(), []
    for d in ("/bin", "/usr/bin", "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu"):
        for p in sorted(Path(d).glob("*")) if Path(d).is_dir() else []:
            try:
                if not p.is_file() or p.is_symlink() or p.stat().st_size > MAX:
                    continue
                with open(p, "rb") as f:
                    if f.read(4) != MAGIC:
                        continue
                real = p.resolve()
                if real in seen:
                    continue
                seen.add(real)
                out.append(p)
            except OSError:
                continue
            if len(out) >= limit:
                return out
    return out


BINARIES = _binaries()


def test_enough_binaries_found():
    if os.environ.get("FM_REQUIRE_LINUX_TESTS") == "1":
        assert len(BINARIES) >= 5, f"only found {len(BINARIES)} ELF binaries to test"
    elif not BINARIES:
        pytest.skip("no ELF binaries found")


@pytest.mark.parametrize("path", BINARIES, ids=[p.name for p in BINARIES])
def test_real_binary_is_not_a_false_positive(path):
    from app import engine, worker
    from app.engine import elf
    from evaluation.cases import verdicts

    data = path.read_bytes()
    # The bounded parser reads real toolchain output without raising.
    parsed = elf.parse(data)
    assert parsed.bits in (32, 64)

    report = engine.correlate(worker.analyse(engine.SCANNERS, data))
    verdict = verdicts(report)["aggregate"]
    high = [f.rule_id for f in report.findings if f.severity.value in ("HIGH", "CRITICAL")]
    assert verdict != "MALICIOUS", f"{path} -> MALICIOUS via {high}"
    assert not high, f"{path} produced HIGH/CRITICAL findings: {high}"
    # elf-structure must have completed (not failed) on genuine binaries.
    status = {s.name: s.status for s in report.scanners}
    assert status["elf-structure"] == "completed"
