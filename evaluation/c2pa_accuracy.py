"""C2PA Content Credentials accuracy study: one change, measured before and after on labelled samples.

Plan, labels, splits and predictions: docs/c2pa-accuracy-preregistration.md (committed before the
engine change). Samples:
  dev         D1 (private APA report: hash in pdf_accuracy.json); the dev entries of
              c2pa_corpus.json: c2pa-rs PDFs (controls), five manifests embedded into PDFs exactly
              as D1 embeds its own ("derived"), c2pa-attacks strings injected into a synthetic
              manifest; the synthetic cases below
  heldout     the held-out entries of c2pa_corpus.json: the official C2PA PDF test file and c2pa-rs
              PDFs, and the manifests of 24 official JPEG test files, derived as above
  regression  the previous study's whole corpus (evaluation.pdf_accuracy.samples)
Each sample is scanned by both engines of two code trees (--before, this checkout), each tree in
its own worker subprocess (evaluation.pdf_accuracy.scan_tree).

    python -m evaluation.c2pa_accuracy --before <checkout of 9882cbf> --public <download dir> \
        --local dev.json --local heldout.json --trials 3 --out <dir>
--public: the directory the corpus was downloaded into, one folder per id (<dir>/<id>/<file name>);
every file is checked against its SHA-256 in c2pa_corpus.json. Downloaded files are only read here,
never imported or run. Nothing is malware: scripts are inert one-liners or comments, "executables"
are four bytes and a word.
"""

import argparse
import hashlib
import io
import json
import platform
import struct
import sys
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from evaluation import pdf_accuracy
from tests.pdf_fixtures import CATALOG, js_action, make_pdf

ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path(__file__).with_name("c2pa_corpus.json")
SUFFIX = bytes.fromhex("00110010800000aa00389b71")  # C2PA JUMBF type UUIDs: 4 characters + this (C2PA 2.2, 11.1)
EMBEDDED = bytes.fromhex("40cb0c32bb8a489da70b2ad6f47f4369")  # JUMBF embedded file content type (ISO 19566-5 B.4)
NAME = "Content Credentials"
SPEC = ("<< /AFRelationship /C2PA_Manifest /Desc (Content Credentials) /F ({n}) /EF << /F {s} 0 R >> "
        "/Subtype (application/c2pa) /Type /Filespec /UF ({n}) >>")  # D1's file specification, byte for byte
NS = 'xmlns="http://www.w3.org/2000/svg"'
ICON = (f'<svg width="16" height="16" viewBox="0 0 16 16" fill="none" {NS}>\n'
        '<path d="M0 0H16V16H0Z" fill="#10A37F"/>\n</svg>\n').encode()


@dataclass(frozen=True)
class Tag:
    tag: int
    value: object


def cbor(v) -> bytes:
    """RFC 8949 encoding of None, bool, int, bytes, str, list, dict and Tag (definite lengths)."""
    def head(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([major << 5 | n])
        size = next(s for s in (1, 2, 4, 8) if n < 1 << (8 * s))
        return bytes([major << 5 | {1: 24, 2: 25, 4: 26, 8: 27}[size]]) + n.to_bytes(size, "big")
    if v is None or isinstance(v, bool):
        return {None: b"\xf6", False: b"\xf4", True: b"\xf5"}[v]
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(map(cbor, v))
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    return head(6, v.tag) + cbor(v.value)


def box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", 8 + len(payload)) + kind + payload


def superbox(uuid: bytes, label: str, *children: bytes, toggles: int = 0x03, extra: bytes = b"") -> bytes:
    """A JUMBF superbox: its description (UUID, toggles, label) and its children (ISO 19566-5 A.2-A.3)."""
    return box(b"jumb", box(b"jumd", uuid + bytes([toggles]) + label.encode() + b"\0" + extra) + b"".join(children))


def c2(code: bytes) -> bytes:
    return code + SUFFIX


def assertion(label: str, value, **kw) -> bytes:
    return superbox(c2(b"cbor"), label, box(b"cbor", cbor(value)), **kw)


def embedded(label: str, media: str, data: bytes, toggles: int = 0, name: bytes = b"") -> bytes:
    return superbox(EMBEDDED, label, box(b"bfdb", bytes([toggles]) + media.encode() + b"\0" + (name and name + b"\0")),
                    box(b"bidb", data))


STANDARD = [assertion("c2pa.actions.v2", {"actions": [{"action": "c2pa.created"}], "allActionsIncluded": True}),
            assertion("c2pa.hash.data", {"exclusions": [{"start": 0, "length": 0}], "name": "jumbf manifest",
                                         "alg": "sha256", "hash": bytes(32), "pad": bytes(8)})]


def manifest(*assertions: bytes, title: str = "FilesMagic synthetic test", kind: bytes = b"c2ma", body: bytes = b"") -> bytes:
    claim = {"instanceID": "xmp:iid:00000000-0000-4000-8000-000000000001",
             "claim_generator_info": {"name": "FilesMagic test", "version": "1"},
             "signature": "self#jumbf=c2pa.signature", "created_assertions": [
                 {"url": "self#jumbf=c2pa.assertions/c2pa.actions.v2", "hash": bytes(32)}],
             "dc:title": title, "alg": "sha256"}
    signature = Tag(18, [cbor({1: -7}), {}, None, bytes(64)])  # COSE_Sign1 shape; nothing is signed
    return superbox(c2(kind), "urn:c2pa:00000000-0000-4000-8000-000000000002",
                    body or (superbox(c2(b"c2as"), "c2pa.assertions", *assertions)
                             + superbox(c2(b"c2cl"), "c2pa.claim.v2", box(b"cbor", cbor(claim)))
                             + superbox(c2(b"c2cs"), "c2pa.signature", box(b"cbor", cbor(signature)))))


def store(*assertions: bytes, title: str = "FilesMagic synthetic test", manifests: tuple[bytes, ...] = ()) -> bytes:
    return superbox(c2(b"c2pa"), "c2pa", *(manifests or (manifest(*STANDARD, *assertions, title=title),)))


def png(after: bytes = b"", bad_crc: bool = False) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) ^ bad_crc)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\x00\x00")) + chunk(b"IEND", b"") + after)


def jpeg(comment: bytes = b"", after: bytes = b"") -> bytes:
    """A 1x1 grey baseline JPEG: one quantisation table, one-code DC and AC Huffman tables, one block."""
    def seg(marker: int, data: bytes) -> bytes:
        return bytes([0xFF, marker]) + struct.pack(">H", len(data) + 2) + data
    table = b"\x01" + b"\x00" * 15 + b"\x00"  # one code of length 1, for symbol 0
    return (b"\xff\xd8" + (seg(0xFE, comment) if comment else b"") + seg(0xDB, b"\x00" + b"\x01" * 64)
            + seg(0xC0, b"\x08\x00\x01\x00\x01\x01\x01\x11\x00") + seg(0xC4, b"\x00" + table)
            + seg(0xC4, b"\x10" + table) + seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + b"\x3f\xff\xd9" + after)


def odt() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text")
        z.writestr("content.xml", '<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:'
                                  'office:1.0"><office:body/></office:document-content>', zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def stream(data: bytes, subtype: str = "/application#2Fc2pa") -> str:  # D1's stream dictionary
    return f"<< /Length {len(data)} /Type /EmbeddedFile /Subtype {subtype} >>\nstream\n{data.decode('latin-1')}\nendstream"


def c2pa_pdf(data: bytes, name: str = NAME, catalog_extra: str = "", page_extra: str = "",
             more: list[tuple[str, int]] = (), objects: dict[int, str] | None = None) -> bytes:
    """A one-page PDF that embeds `data` as D1 embeds its manifest: catalog /AF and /EmbeddedFiles,
    file specification object 5, stream object 6. `more`: further (name, file specification) entries."""
    entries = " ".join(f"({n}) {o} 0 R" for n, o in sorted([(name, 5), *more]))
    return make_pdf(catalog_extra=f"/AF [5 0 R] /Names << /EmbeddedFiles << /Names [{entries}] >> >> {catalog_extra}",
                    page_extra=page_extra, objects={5: SPEC.format(n=name, s=6), 6: stream(data), **(objects or {})})


def manifest_store(data: bytes) -> bytes | None:
    """A JPEG's C2PA manifest store: its APP11 JUMBF packets (CI "JP", En, Z, then the box; later
    packets repeat the box header) reassembled (C2PA 2.2, A.3). A .c2pa file is the store itself."""
    if data[4:8] == b"jumb":
        return data
    if data[:2] != b"\xff\xd8":
        return None
    i, packets = 2, {}
    while i + 4 <= len(data) and data[i] == 0xFF and data[i + 1] not in (0xD9, 0xDA):
        n = struct.unpack_from(">H", data, i + 2)[0]
        seg = data[i + 4:i + 2 + n]
        if data[i + 1] == 0xEB and seg[:2] == b"JP":
            en, z = struct.unpack_from(">HI", seg, 2)
            packets.setdefault(en, []).append((z, seg[8:]))
        i += 2 + n
    for parts in packets.values():
        parts.sort()
        first = parts[0][1]
        head = 16 if struct.unpack_from(">I", first)[0] == 1 else 8
        body = first + b"".join(p[head:] for _, p in parts[1:])
        if body[4:8] == b"jumb" and b"c2pa\0" in body[:64]:
            return body
    return None


def _incremental_add() -> bytes:
    """A PDF without a manifest, then an incremental update that rewrites the catalog under the same
    number and generation and adds the manifest: the old catalog's bytes stay in the file."""
    base = make_pdf()
    prev, at = int(base.rsplit(b"startxref", 1)[1].split()[0]), len(base)
    update = (b"1 0 obj\n" + CATALOG.format(extra=f"/AF [5 0 R] /Names << /EmbeddedFiles << /Names [({NAME}) 5 0 R] >> >>")
              .encode() + b"\nendobj\n")
    offsets = [at, at + len(update)]
    update += b"5 0 obj\n" + SPEC.format(n=NAME, s=6).encode() + b"\nendobj\n"
    offsets.append(at + len(update))
    update += b"6 0 obj\n" + stream(store()).encode("latin-1") + b"\nendobj\n"
    xref = at + len(update)
    update += (b"xref\n0 2\n0000000000 65535 f \n%010d 00000 n \n5 2\n%010d 00000 n \n%010d 00000 n \n"
               b"trailer\n<< /Size 7 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n"
               % (offsets[0], offsets[1], offsets[2], prev, xref))
    return base + update


def _svg(markup: str) -> bytes:
    return store(embedded("c2pa.icon", "image/svg+xml", markup.encode()))


def synthetic() -> list[dict]:
    s = lambda id, cls, made, data: dict(id=id, cls=cls, construction=made, data=data)  # noqa: E731
    deep = assertion("c2pa.actions", {"actions": []})
    for i in range(9):
        deep = superbox(c2(b"c2xx"), f"level{i}", deep)
    salted = b"\0\0\0\x18c2sh" + bytes(16)
    exe = b"MZ\x90\x00inert"
    script_link = "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] /A << /S /JavaScript /JS (app.alert\\(1\\);) >> >>"
    return [
        s("C01-cbor-only", "c2pa-benign", "claim, signature, c2pa.actions.v2 and c2pa.hash.data (CBOR)", c2pa_pdf(store())),
        s("C02-jpeg-thumbnail", "c2pa-benign", "plus a JPEG claim thumbnail",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg", jpeg())))),
        s("C03-png-thumbnail", "c2pa-benign", "plus a PNG thumbnail",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.png", "image/png", png())))),
        s("C04-static-svg-icon", "c2pa-benign", "plus a static SVG c2pa.icon (svg, path), as D1",
          c2pa_pdf(store(embedded("c2pa.icon", "image/svg+xml", ICON)))),
        s("C05-json-assertion", "c2pa-benign", "plus a JSON schema.org CreativeWork assertion",
          c2pa_pdf(store(superbox(c2(b"json"), "stds.schema-org.CreativeWork", box(b"json",
                   b'{"@context": "https://schema.org", "@type": "CreativeWork", "author": [{"name": "Test"}]}'))))),
        s("C06-salt-and-padding", "c2pa-benign", "c2sh salt in descriptions (toggles 0x13) and a zero padding box",
          c2pa_pdf(store(assertion("c2pa.ingredient", {"relationship": "parentOf"}, toggles=0x13, extra=salted)
                         + box(b"free", bytes(16))))),
        s("C07-named-manifest-c2pa", "c2pa-benign", "the store named manifest.c2pa", c2pa_pdf(store(), name="manifest.c2pa")),
        s("C08-two-manifest-stores", "c2pa-benign", "two manifest stores, two attachments",
          c2pa_pdf(store(), more=[("Content Credentials 2", 7)],
                   objects={7: SPEC.format(n="Content Credentials 2", s=8), 8: stream(store(title="second"))})),
        s("C09-with-verified-odt", "c2pa-benign", "a manifest store and an OpenDocument text without code",
          c2pa_pdf(store(), more=[("plan.odt", 7)], objects={
              7: "<< /Type /Filespec /F (plan.odt) /UF (plan.odt) /EF << /F 8 0 R >> >>",
              8: stream(odt(), "/application#2Fvnd.oasis.opendocument.text")})),
        s("C10-svg-script", "c2pa-active", "c2pa.icon SVG with a script element",
          c2pa_pdf(_svg(f"<svg {NS}><script>/* inert */</script></svg>"))),
        s("C11-svg-onload", "c2pa-active", "SVG with an onload attribute",
          c2pa_pdf(_svg(f'<svg {NS} onload="void 0"><path d="M0 0"/></svg>'))),
        s("C12-svg-foreign-object", "c2pa-active", "SVG with foreignObject holding HTML",
          c2pa_pdf(_svg(f'<svg {NS}><foreignObject><div xmlns="http://www.w3.org/1999/xhtml">x</div></foreignObject>'
                        "</svg>"))),
        s("C13-svg-javascript-link", "c2pa-active", "SVG a element with a javascript: link",
          c2pa_pdf(_svg(f'<svg {NS} xmlns:xlink="http://www.w3.org/1999/xlink"><a xlink:href="javascript:void(0)">'
                        '<path d="M0 0"/></a></svg>'))),
        s("C14-svg-external-image", "c2pa-active", "SVG image loading an external picture",
          c2pa_pdf(_svg(f'<svg {NS}><image href="https://example.invalid/x.png" width="1" height="1"/></svg>'))),
        s("C15-svg-style", "c2pa-active", "SVG style element importing a style sheet",
          c2pa_pdf(_svg(f"<svg {NS}><style>@import url(https://example.invalid/x.css);</style></svg>"))),
        s("C16-svg-stylesheet-instruction", "c2pa-active", "an xml-stylesheet processing instruction",
          c2pa_pdf(_svg(f'<?xml-stylesheet href="https://example.invalid/x.css"?><svg {NS}><path d="M0 0"/></svg>'))),
        s("C17-svg-dtd-entity", "c2pa-active", "SVG with a DTD defining an entity",
          c2pa_pdf(_svg(f'<!DOCTYPE svg [<!ENTITY e "x">]><svg {NS}><title>&e;</title></svg>'))),
        s("C18-svg-external-use", "c2pa-active", "SVG use of an external document",
          c2pa_pdf(_svg(f'<svg {NS}><use href="https://example.invalid/x.svg#a"/></svg>'))),
        s("C19-svg-set-href", "c2pa-active", "SVG set changing an href to javascript:",
          c2pa_pdf(_svg(f'<svg {NS}><a><set attributeName="href" to="javascript:void(0)"/><path d="M0 0"/></a></svg>'))),
        s("C20-svg-external-fill", "c2pa-active", "a fill url() pointing to another document",
          c2pa_pdf(_svg(f'<svg {NS}><path d="M0 0" fill="url(https://example.invalid/p.svg#g)"/></svg>'))),
        s("C21-html-in-data-box", "c2pa-active", "an HTML document as embedded data (text/html)",
          c2pa_pdf(store(embedded("c2pa.icon", "text/html", b"<!DOCTYPE html><html><script>/* inert */</script></html>")))),
        s("C22-xss-in-claim-title", "c2pa-active", "a script element in the claim's dc:title",
          c2pa_pdf(store(title="<script>/* inert */</script>"))),
        s("C23-bidi-override-in-label", "c2pa-active", "a right-to-left override in an assertion label",
          c2pa_pdf(store(assertion("c2pa.actions‮", {"actions": []})))),
        s("C24-user-link-javascript", "c2pa-active", "a valid store, and a page link that runs JavaScript",
          c2pa_pdf(store(), page_extra="/Annots [7 0 R]", objects={7: script_link})),
        s("C30-mz-declared-jpeg", "c2pa-deceptive", "MZ bytes as a thumbnail declared image/jpeg",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg", exe)))),
        s("C31-jpeg-html-after-eoi", "c2pa-deceptive", "a JPEG thumbnail with an HTML document after EOI",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg",
                                  jpeg(after=b"<html><script>/* inert */</script></html>"))))),
        s("C32-jpeg-script-in-comment", "c2pa-deceptive", "a JPEG whose comment segment holds a script element",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg", jpeg(comment=b"<script>/* inert */</script>"))))),
        s("C33-png-zip-after-iend", "c2pa-deceptive", "a PNG thumbnail with a ZIP header after IEND",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.png", "image/png", png(after=b"PK\x03\x04inert"))))),
        s("C34-declared-png-holds-jpeg", "c2pa-deceptive", "image/png declared, JPEG bytes",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.png", "image/png", jpeg())))),
        s("C35-external-reference", "c2pa-deceptive", "a file description with the external-reference toggle",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg", b"https://example.invalid/t.jpg", toggles=2)))),
        s("C36-mz-as-c2pa-manifest", "c2pa-deceptive", "MZ bytes under /AFRelationship /C2PA_Manifest, named "
          "Content Credentials", c2pa_pdf(exe)),
        s("C37-store-named-html", "c2pa-deceptive", "a valid store named Content Credentials.html",
          c2pa_pdf(store(), name="Content Credentials.html")),
        s("C38-uuid-content-box", "c2pa-deceptive", "a custom assertion with a uuid content box",
          c2pa_pdf(store(superbox(c2(b"uuid"), "com.example.custom", box(b"uuid", bytes(16) + b"opaque data"))))),
        s("C39-compressed-manifest", "c2pa-deceptive", "a Brotli-compressed (brob) manifest",
          c2pa_pdf(store(manifests=(manifest(kind=b"c2cm", body=box(b"brob", b"\x0b\x02\x80inert")),)))),
        s("C40-not-a-manifest-store", "c2pa-deceptive", "a first superbox with the manifest UUID, labelled c2pa",
          c2pa_pdf(superbox(c2(b"c2ma"), "c2pa", *STANDARD))),
        s("C50-truncated", "c2pa-malformed", "the store cut 10 bytes short", c2pa_pdf(store()[:-10])),
        s("C51-trailing-bytes", "c2pa-malformed", "4 bytes after the store", c2pa_pdf(store() + b"\0\0\0\0")),
        s("C52-box-beyond-parent", "c2pa-malformed", "a content box longer than its superbox",
          c2pa_pdf(superbox(c2(b"c2pa"), "c2pa", struct.pack(">I", 1000) + b"cbor" + cbor({})))),
        s("C53-nesting-too-deep", "c2pa-malformed", "superboxes nested 13 deep", c2pa_pdf(store(deep))),
        s("C54-too-many-boxes", "c2pa-malformed", "10,001 padding boxes",
          c2pa_pdf(superbox(c2(b"c2pa"), "c2pa", box(b"free", b"") * 10_001))),
        s("C55-cbor-trailing", "c2pa-malformed", "a CBOR box with a byte after its data item",
          c2pa_pdf(store(superbox(c2(b"cbor"), "c2pa.actions", box(b"cbor", cbor({}) + b"\x00"))))),
        s("C56-cbor-invalid-utf8", "c2pa-malformed", "a CBOR text string that is not UTF-8",
          c2pa_pdf(store(superbox(c2(b"cbor"), "c2pa.actions", box(b"cbor", b"\x62\xff\xfe"))))),
        s("C57-cbor-repeated-key", "c2pa-malformed", "a CBOR map with the key a twice",
          c2pa_pdf(store(superbox(c2(b"cbor"), "c2pa.actions", box(b"cbor", b"\xa2\x61a\x01\x61a\x02"))))),
        s("C58-cbor-unterminated", "c2pa-malformed", "an indefinite CBOR array without its break",
          c2pa_pdf(store(superbox(c2(b"cbor"), "c2pa.actions", box(b"cbor", b"\x9f\x01\x02"))))),
        s("C59-json-repeated-key", "c2pa-malformed", "a JSON object with the key a twice",
          c2pa_pdf(store(superbox(c2(b"json"), "stds.schema-org.CreativeWork", box(b"json", b'{"a": 1, "a": 2}'))))),
        s("C60-png-bad-crc", "c2pa-malformed", "a PNG thumbnail with wrong CRCs",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.png", "image/png", png(bad_crc=True))))),
        s("C61-jpeg-without-eoi", "c2pa-malformed", "a JPEG thumbnail without EOI",
          c2pa_pdf(store(embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg", jpeg()[:-2])))),
        s("C70-auto-js-exports-manifest", "dangerous", "a valid store, and /OpenAction JavaScript exportDataObject of it",
          c2pa_pdf(store(), catalog_extra="/OpenAction 7 0 R",
                   objects={7: js_action(f'this.exportDataObject\\({{cName: "{NAME}", nLaunch: 2}}\\);')})),
        s("C71-auto-launch-manifest", "dangerous", "a valid store, and /OpenAction /Launch of its file specification",
          c2pa_pdf(store(), catalog_extra="/OpenAction << /S /Launch /F 5 0 R >>")),
        s("C72-with-text-attachment", "attachment", "a valid store, and a text attachment",
          c2pa_pdf(store(), more=[("notes.txt", 7)], objects={
              7: "<< /Type /Filespec /F (notes.txt) /UF (notes.txt) /EF << /F 8 0 R >> >>",
              8: stream(b"inert attachment text", "/text#2Fplain")})),
        s("C73-added-by-incremental-update", "ambiguous", "a valid store added by an incremental update that rewrites "
          "the catalog under the same number and generation", _incremental_add()),
    ]


def attack_samples(path: Path, sid: str) -> list[dict]:
    """One PDF per c2pa-attacks string: a synthetic benign manifest whose claim title is that string."""
    lines = [line for line in path.read_bytes().decode("utf-8").split("\n") if line]
    return [dict(id=f"{sid}-{k:02d}", cls="attack-string", construction=f"{path.name} line {k}",
                 data=c2pa_pdf(store(title=line))) for k, line in enumerate(lines, 1)]


def samples(local: list[Path], public: Path, tmp: Path) -> list[dict]:
    rows = pdf_accuracy.samples(local, tmp)
    for r in rows:  # the previous study's corpus: regression here, except D1, the problem sample
        r["split"] = "dev" if r["id"] == "D1" else "regression"
    built = []
    for e in json.loads(CORPUS.read_text())["files"]:
        path = public / e["id"] / e["path"].rsplit("/", 1)[-1]
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != e["sha256"]:
            raise SystemExit(f"{e['id']}: SHA-256 differs from {CORPUS.name}")
        if e["role"] in ("c2pa-pdf", "control-pdf"):
            rows.append(dict(id=e["id"], split=e["split"], cls="benign", fmt="pdf", path=str(path)))
        elif e["role"] == "manifest-source":
            if (found := manifest_store(data)) is None:
                raise SystemExit(f"{e['id']}: no C2PA manifest store found")
            built.append(dict(id=f"{e['id']}-derived", split=e["split"], cls="c2pa-benign", data=c2pa_pdf(found),
                              construction=f"the manifest store of {e['path'].rsplit('/', 1)[-1]} ({len(found)} bytes)"))
        else:
            built += [dict(a, split="dev") for a in attack_samples(path, e["id"])]
    built += [dict(c, split="dev") for c in synthetic()]
    for c in built:
        (path := tmp / f"{c['id']}.pdf").write_bytes(c.pop("data"))
        rows.append(c | {"fmt": "pdf", "path": str(path)})
    return rows


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--before", type=Path, required=True, help="checkout of the baseline (9882cbf)")
    parser.add_argument("--public", type=Path, required=True, help="download directory of c2pa_corpus.json")
    parser.add_argument("--local", type=Path, action="append", default=[], help="JSON list of {id, path}")
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as tmp:
        rows = samples(args.local, args.public, Path(tmp))
        paths = [r["path"] for r in rows]
        for tag, tree in (("before", args.before), ("after", ROOT)):
            for r, result in zip(rows, pdf_accuracy.scan_tree(tree, paths, args.trials)):
                r[tag] = result
    env = {"platform": platform.platform(), "python": sys.version.split()[0], "trials": args.trials,
           **{tag: {"commit": pdf_accuracy.git(tree, "rev-parse", "HEAD"),
                    "dirty": bool(pdf_accuracy.git(tree, "status", "--porcelain"))}
              for tag, tree in (("before", args.before), ("after", ROOT))}}
    summary = pdf_accuracy.summarise(rows)
    args.out.mkdir(parents=True, exist_ok=True)
    for r in rows:
        r.pop("path")
    (args.out / "results.json").write_text(json.dumps({"environment": env, "rows": rows}, indent=1))
    (args.out / "summary.json").write_text(json.dumps({"environment": env, **summary}, indent=1))
    text = pdf_accuracy.markdown(summary, env, title="C2PA accuracy study")
    (args.out / "summary.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
