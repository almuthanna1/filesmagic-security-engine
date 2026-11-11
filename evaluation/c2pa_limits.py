"""Worst cases at the limits of docs/c2pa-accuracy-preregistration.md section 2 point 1: each a PDF
whose attachments are FlateDecode streams, scanned by the unified engine (the code the worker runs,
in-process). Run from a checkout: python -B -m evaluation.c2pa_limits [--quick] [--write DIR].

Each case is built here and scanned in a fresh process (stopped after 300 s) that first scans a
small PDF (warm-up: rules compiled, modules loaded), then the case `trials` times (3, or 1 with
--quick). Memory is that process's peak: peak working set and peak private (committed) bytes on
Windows, maximum resident set on Linux; "added" is the peak minus the warm-up peak. --write keeps
the PDFs. Evidence: docs/evidence/c2pa-accuracy-e2eb2c7/limits-*.md."""

import os
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, os.getcwd())

from evaluation.c2pa_accuracy import SPEC, box, c2, cbor, embedded, jpeg, png, store, superbox  # noqa: E402
from tests.pdf_fixtures import make_pdf  # noqa: E402

BUDGET = 16 * 1024 * 1024 - 4096  # what a store may hold: the shared read budget, less the store's own boxes


def flate(data: bytes) -> str:
    z = zlib.compress(data, 9)
    return (f"<< /Length {len(z)} /Filter /FlateDecode /Type /EmbeddedFile /Subtype /application#2Fc2pa >>\n"
            f"stream\n{z.decode('latin-1')}\nendstream")


def pdf(*stores: bytes) -> bytes:
    objects, entries = {}, []
    for k, s in enumerate(stores):
        name = f"Content Credentials {k:03d}"
        objects[5 + 2 * k], objects[6 + 2 * k] = SPEC.format(n=name, s=6 + 2 * k), flate(s)
        entries.append((name, 5 + 2 * k))
    names = " ".join(f"({n}) {o} 0 R" for n, o in entries)
    return make_pdf(catalog_extra=f"/AF [{' '.join(f'{o} 0 R' for _, o in entries)}] "
                                  f"/Names << /EmbeddedFiles << /Names [{names}] >> >>", objects=objects)


def raw(kind: bytes, payload: bytes) -> bytes:  # one assertion holding one content box
    return store(superbox(c2(b"cbor"), "c2pa.test", box(kind, payload)))


def picture(media: str, data: bytes) -> bytes:
    return store(embedded("c2pa.thumbnail.claim", media, data))


def svg(elements: int, d_len: int) -> bytes:
    path = f'<path d="M0 0{" L1 1" * (d_len // 5)}"/>'
    return f'<svg xmlns="http://www.w3.org/2000/svg">{path * (elements - 1)}</svg>'.encode()


def png_chunks(n: int) -> bytes:
    return png()[:-12] + (b"\x00\x00\x00\x00tEXt" + zlib.crc32(b"tEXt").to_bytes(4, "big")) * n + png()[-12:]


def markup_jpeg(n: int) -> bytes:  # image data without FF that a markup search must read through
    return J[:-3] + b"\x3f" + b"/onaaaaaaa" * (n // 10) + b"\xff\xd9"


def combined() -> list[bytes]:
    """Every per-PDF limit nearly reached in one PDF, the rest of the read budget in one picture."""
    parts = [raw(b"cbor", cbor([0] * 99_000)),  # CBOR items
             store(superbox(c2(b"cbor"), "c2pa.test", box(b"cbor", b"\x00"), *[box(b"free", b"")] * 9_800)),  # boxes
             raw(b"cbor", cbor("A" * 800_000)),  # text (shared with the SVG values)
             raw(b"json", b"[" + b" " * 900_000 + b"0]"),  # JSON bytes
             picture("image/svg+xml", svg(9_990, 15)),  # SVG elements
             picture("image/png", png_chunks(99_000))]  # PNG chunks (shared with JPEG markers)
    return parts + [picture("image/jpeg", markup_jpeg(BUDGET - sum(map(len, parts)) - 4096))]


J = jpeg()  # ... SOS, one entropy byte 3f, EOI
CASES = {
    "boxes: 10,000 in one store": lambda: [store(superbox(c2(b"cbor"), "c2pa.test", box(b"cbor", b"\x00"),
                                                          *[box(b"free", b"")] * 9_980))],
    "boxes: one superbox of 2 million empty boxes": lambda: [store(superbox(c2(b"cbor"), "c2pa.test",
                                                                            *[box(b"free", b"")] * (BUDGET // 8)))],
    "boxes: 100 stores of 10,000": lambda: [store(superbox(c2(b"cbor"), "c2pa.test", box(b"cbor", b"\x00"),
                                                           *[box(b"free", b"")] * 9_980))] * 100,
    "CBOR: 100,000 items in one store": lambda: [raw(b"cbor", cbor([0] * 99_900))],
    "CBOR: 100 stores of 100,000 items": lambda: [raw(b"cbor", cbor([0] * 99_900))] * 100,
    "CBOR: indefinite text of 16 million empty chunks": lambda: [raw(b"cbor", b"\x7f" + b"\x60" * (BUDGET - 2) + b"\xff")],
    "CBOR: nesting 64 deep": lambda: [raw(b"cbor", b"\x81" * 63 + b"\x00")],
    "JSON: 8 million values in one box": lambda: [raw(b"json", b"[" + b"0," * (BUDGET // 2 - 1) + b"0]")],
    "text: 1 MiB in one string": lambda: [raw(b"cbor", cbor("A" * ((1 << 20) - 2_000)))],
    "text: 16 stores of 1 MiB": lambda: [raw(b"cbor", cbor("A" * ((1 << 20) - 2_000)))] * 16,
    "SVG: 10,000 elements, 1 MiB of values": lambda: [picture("image/svg+xml", svg(10_000, 100))],
    "SVG: 50 stores of 10,000 elements": lambda: [picture("image/svg+xml", svg(10_000, 25))] * 50,
    "JPEG: 16 MiB of fill bytes": lambda: [picture("image/jpeg", J[:-2] + b"\xff" * BUDGET + b"\xff\xd9")],
    "JPEG: 8 million stuffed FF00 pairs": lambda: [picture("image/jpeg", J[:-3] + b"\x3f" + b"\xff\x00" * (BUDGET // 2)
                                                           + b"\xff\xd9")],
    "JPEG: 4 million empty COM segments": lambda: [picture("image/jpeg", J[:2] + b"\xff\xfe\x00\x02" * (BUDGET // 4)
                                                           + J[2:])],
    "JPEG: 16 MiB of entropy data like markup": lambda: [picture("image/jpeg", markup_jpeg(BUDGET))],
    "PNG: 1.4 million empty chunks": lambda: [picture("image/png", png_chunks(BUDGET // 12))],
    "PNG: one 16 MiB IDAT": lambda: [picture("image/png", png()[:33] + len(z := bytes(BUDGET)).to_bytes(4, "big")
                                             + b"IDAT" + z + zlib.crc32(b"IDAT" + z).to_bytes(4, "big") + png()[-12:])],
    "all limits at once: 7 stores": combined,
}


def peak_mb() -> tuple[float, float]:
    """(peak working set or max RSS, peak private bytes or the same) of this process, in MiB."""
    if sys.platform != "win32":
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        return rss, rss
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (n, ctypes.c_size_t) for n in ("PeakWorkingSetSize", "WorkingSetSize", "QuotaPeakPagedPoolUsage",
                                           "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                                           "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]
    c = Counters(cb=ctypes.sizeof(Counters))
    kernel32, psapi = ctypes.WinDLL("kernel32"), ctypes.WinDLL("psapi")
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    return c.PeakWorkingSetSize / 2**20, c.PeakPagefileUsage / 2**20


def scan(path: str, trials: int) -> str:
    """One row: verdict, attachment rule and first reason, time, memory. Runs in its own process."""
    from app import engine, worker
    from evaluation.cases import verdicts
    engine.correlate(worker.analyse(engine.SCANNERS, pdf(store())))  # warm-up
    base = peak_mb()
    data, times = open(path, "rb").read(), []
    for _ in range(trials):
        t = time.perf_counter()
        report = engine.correlate(worker.analyse(engine.SCANNERS, data))
        times.append((time.perf_counter() - t) * 1000)
    peak = peak_mb()
    found = [f for f in report.findings if f.rule_id.startswith("ENGINE_PDF_ATTACHMENTS")]
    why = next((e.split(": not verified: ", 1)[1] for f in found for e in f.evidence if ": not verified: " in e),
               "every store verified" if found and found[0].rule_id.endswith("VERIFIED") else "")
    return (f"{verdicts(report)['aggregate']} | {', '.join(f.rule_id for f in found)} | {max(times):,.0f} | "
            f"{peak[0]:,.0f} / {peak[1]:,.0f} | {peak[0] - base[0]:,.0f} / {peak[1] - base[1]:,.0f} | {why[:110]}")


def main() -> None:
    trials = 1 if "--quick" in sys.argv else 3
    if "--scan" in sys.argv:
        print(scan(sys.argv[sys.argv.index("--scan") + 1], trials), flush=True)
        return
    keep = sys.argv[sys.argv.index("--write") + 1] if "--write" in sys.argv else None
    print(f"| case | store bytes | PDF bytes | verdict | attachment rule | unified scan, max of {trials} (ms) | "
          "peak memory, MiB (working set / private) | added by the case | first reason a store was not verified |")
    print("|---|---|---|---|---|---|---|---|---|", flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        for k, (name, build) in enumerate(CASES.items(), 1):
            stores = build()
            path = os.path.join(keep or tmp, f"limits-{k:02d}.pdf")
            with open(path, "wb") as f:
                f.write(pdf(*stores))
            head = f"| {name} | {len(stores[0]):,} x {len(stores)} | {os.path.getsize(path):,} | "
            del stores
            try:
                done = subprocess.run([sys.executable, "-B", __file__, "--scan", path, *sys.argv[1:]], text=True,
                                      capture_output=True, timeout=300)
                print(head + (done.stdout.strip() or f"failed: {done.stderr.strip()[-200:]}") + " |", flush=True)
            except subprocess.TimeoutExpired:
                print(head + "| | over 300,000 (stopped) | | | |", flush=True)


if __name__ == "__main__":
    main()
