"""25 MiB inert PDF worker capacity canary, meant for a 512 MiB Docker cgroup.

This is a memory/performance canary, NOT a substitute for production Linux
namespace isolation tests. Docker's default seccomp can prohibit unshare(),
so no receipt is issued here. Use an actual strict hosted probe separately.
"""

import asyncio
import io
import os
import resource
import time

from pypdf import PdfWriter

from app import worker
from app.engine import SCANNERS

LIMIT = 25 * 1024 * 1024


def sample() -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(612, 792)
    # Inert, non-compressible bytes exercise embedded-file parsing and memory.
    writer.add_attachment(filename="inert-data.bin", data=os.urandom(24 * 1024 * 1024 + 768 * 1024))
    result = io.BytesIO()
    writer.write(result)
    payload = result.getvalue()
    # Test a real, structurally valid near-limit PDF instead of adding trailing
    # padding, which can make pypdf reject an otherwise valid document.
    assert 24 * 1024 * 1024 <= len(payload) <= LIMIT, len(payload)
    return payload


async def check() -> None:
    data = sample()
    started = time.monotonic()
    report = await worker.run(data, engine="unified")
    duration = time.monotonic() - started
    statuses = {s.name: s.status for s in report.scanners}
    failed = [s for s in report.scanners if s.status == "failed"]
    print({"bytes": len(data), "duration_seconds": round(duration, 2),
           "worker_mem_limit_mb": worker.MEMORY_MB,
           "max_rss_kib_children": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
           "scanners_reported": len(report.scanners), "failed": len(failed),
           "failed_statuses": {s.name: (s.error_kind, s.error_type) for s in failed}})
    assert len(report.scanners) == len(SCANNERS), "incomplete scanner roster"
    assert not failed, "25 MiB benign PDF caused a scanner failure"
    assert report.isolation.get("rlimits"), "worker did not enforce rlimits"


if __name__ == "__main__":
    asyncio.run(check())
