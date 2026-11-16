"""Near-25 MiB inert PDF worker capacity canary for a 512 MiB Docker cgroup.

Two cases isolate resource capacity from parser safety policy:
* normal: four bounded attachments, each below the configured 20 MiB PDF
  decoded-stream ceiling. All scanners must finish under the container limit.
* over-stream: a valid PDF with one 24+ MiB embedded stream. Parsers must
  report document limits as expected, not unexpected internal crashes or a
  fully covered SAFE result. Do NOT loosen the decompression ceiling.

This does not verify Linux user+network namespace isolation, which must still
pass its own Linux CI and signed receipt probe on the deployed host.
"""
import asyncio
import io
import os
import resource
import sys
import time

from pypdf import PdfWriter

from app import worker
from app.engine import SCANNERS

LIMIT = 25 * 1024 * 1024


def sample(case: str) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(612, 792)
    if case == "normal":
        for i in range(4):
            # PDF attachment names are deliberately non-executable, and each
            # stream remains beneath the independent pypdf parser ceiling.
            writer.add_attachment(filename=f"inert-{i}.txt", data=os.urandom(6 * 1024 * 1024))
    elif case == "over-stream":
        writer.add_attachment(filename="inert.txt", data=os.urandom(24 * 1024 * 1024 + 768 * 1024))
    else:
        raise ValueError(f"unknown case: {case}")
    result = io.BytesIO()
    writer.write(result)
    payload = result.getvalue()
    assert 24 * 1024 * 1024 <= len(payload) <= LIMIT, (case, len(payload))
    return payload


async def check(case: str) -> None:
    data = sample(case)
    started = time.monotonic()
    report = await worker.run(data, engine="unified")
    duration = time.monotonic() - started
    failed = [s for s in report.scanners if s.status == "failed"]
    rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    print({"case": case, "bytes": len(data), "duration_seconds": round(duration, 2),
           "worker_mem_limit_mb": worker.MEMORY_MB, "max_rss_kib_children": rss,
           "scanners_reported": len(report.scanners), "failed": len(failed),
           "failed_statuses": {s.name: (s.error_kind, s.error_type) for s in failed},
           "coverage_complete": report.coverage_complete}, flush=True)
    assert len(report.scanners) == len(SCANNERS), "incomplete scanner roster"
    assert report.isolation.get("rlimits"), "worker failed to enforce rlimits"
    if case == "normal":
        assert not failed, "PDF with bounded attachments failed a scanner"
    else:
        assert failed, "per-stream safety ceiling unexpectedly relaxed"
        assert all(s.error_kind == "invalid_structure" for s in failed), "resource limit caused an internal crash"
        assert not report.coverage_complete, "truncated parser coverage must never report complete"


if __name__ == "__main__":
    asyncio.run(check(sys.argv[1]))
