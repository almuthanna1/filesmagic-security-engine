"""Worst cases at the limits of docs/c2pa-accuracy-preregistration.md section 2 point 1: each a PDF
whose attachments are FlateDecode streams, scanned in-process by the unified engine. Run from a
checkout: python -B -m evaluation.c2pa_limits [--quick] (one trial instead of 3). Each case runs in its own
process, stopped after 300 s. Evidence: docs/evidence/c2pa-accuracy-e2eb2c7/limits-*.md."""

import os
import subprocess
import sys
import time
import zlib

sys.path.insert(0, os.getcwd())

from app import engine, worker  # noqa: E402
from app.engine import c2pa  # noqa: E402
from evaluation.c2pa_accuracy import SPEC, box, c2, cbor, embedded, jpeg, png, store, superbox  # noqa: E402
from evaluation.cases import verdicts  # noqa: E402
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
    "JPEG: 16 MiB of entropy data like markup": lambda: [picture("image/jpeg", J[:-3] + b"\x3f"
                                                                 + b"/onaaaaaaa" * (BUDGET // 10) + b"\xff\xd9")],
    "PNG: 1.4 million empty chunks": lambda: [picture("image/png", png()[:-12] + (b"\x00\x00\x00\x00tEXt"
                                                       + zlib.crc32(b"tEXt").to_bytes(4, "big")) * (BUDGET // 12)
                                                      + png()[-12:])],
    "PNG: one 16 MiB IDAT": lambda: [picture("image/png", png()[:33] + len(z := bytes(BUDGET)).to_bytes(4, "big")
                                             + b"IDAT" + z + zlib.crc32(b"IDAT" + z).to_bytes(4, "big") + png()[-12:])],
}


def row(name: str, trials: int) -> str:
    stores = CASES[name]()
    data = pdf(*stores)
    try:
        what = "verified"
        c2pa.verify(stores[0])
    except c2pa.NotVerified as e:
        what = f"not verified: {str(e)[:90]}"
    times = []
    for _ in range(trials):
        t = time.perf_counter()
        report = engine.correlate(worker.analyse(engine.SCANNERS, data))
        times.append((time.perf_counter() - t) * 1000)
    found = [f.rule_id for f in report.findings if f.rule_id.startswith("ENGINE_PDF_ATTACHMENTS")]
    return (f"| {name} | {len(stores[0]):,} x {len(stores)} | {len(data):,} | {verdicts(report)['aggregate']} "
            f"{', '.join(found)} | {max(times):,.0f} | {what} |")


def main() -> None:
    trials = 1 if "--quick" in sys.argv else 3
    if "--case" in sys.argv:
        print(row(sys.argv[sys.argv.index("--case") + 1], trials), flush=True)
        return
    print(f"| case | store bytes | PDF bytes | verdict | unified scan, max of {trials} (ms) | the C2PA check on the first store |")
    print("|---|---|---|---|---|---|", flush=True)
    for name in CASES:
        try:
            done = subprocess.run([sys.executable, "-B", __file__, "--case", name, *sys.argv[1:]], capture_output=True,
                                  text=True, timeout=300)
            print(done.stdout.strip() or f"| {name} | failed: {done.stderr.strip()[-200:]} |", flush=True)
        except subprocess.TimeoutExpired:
            print(f"| {name} | | | | over 300,000 (stopped) | |", flush=True)


if __name__ == "__main__":
    main()
