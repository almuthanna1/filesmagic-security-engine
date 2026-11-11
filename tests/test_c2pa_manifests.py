"""C2PA manifest stores (app.engine.c2pa): verified only when every item is data or a picture without
active content, read completely under fixed limits (docs/c2pa-accuracy-preregistration.md). Inert
fixtures: scripts are comments, "executables" four bytes and a word."""

import pytest

from app import engine, worker
from app.engine import c2pa
from app.engine.correlate import ACCOUNTS
from app.models import Severity
from app.scanners import SCANNERS
from evaluation.c2pa_accuracy import (
    ICON, NS, assertion, box, c2, c2pa_pdf, cbor, embedded, jpeg, png, store, superbox, synthetic,
)
from evaluation.cases import verdicts
from evaluation.pdf_accuracy import outcome

CASES = {s["id"]: s for s in synthetic()}
VERIFIED, UNVERIFIED = "ENGINE_PDF_ATTACHMENTS_VERIFIED", "ENGINE_PDF_ATTACHMENTS_UNVERIFIED"
# What the evidence must say for each case not verified by the C2PA check itself (the first item that failed).
REASONS = {
    "C10-svg-script": "element 'script'", "C11-svg-onload": "attribute 'onload'",
    "C12-svg-foreign-object": "element 'foreignObject'", "C13-svg-javascript-link": "element 'a'",
    "C14-svg-external-image": "element 'image'", "C15-svg-style": "element 'style'",
    "C16-svg-stylesheet-instruction": "processing instruction", "C17-svg-dtd-entity": "DTDForbidden",
    "C18-svg-external-use": "element 'use'", "C19-svg-set-href": "element 'a'", "C20-svg-external-fill": "can refer outside",
    "C21-html-in-data-box": "DTDForbidden", "C22-xss-in-claim-title": "text with markup",
    "C23-bidi-override-in-label": "control or formatting character", "C30-mz-declared-jpeg": "not a JPEG, PNG or SVG",
    "C31-jpeg-html-after-eoi": "bytes after its end", "C32-jpeg-script-in-comment": "a polyglot",
    "C33-png-zip-after-iend": "bytes after IEND", "C34-declared-png-holds-jpeg": "declares 'image/png' but holds JPEG",
    "C35-external-reference": "points to an external file", "C36-mz-as-c2pa-manifest": "not an OpenDocument package",
    "C37-store-named-html": "under a name with another extension", "C38-uuid-content-box": "a 'uuid' box",
    "C39-compressed-manifest": "a 'brob' box", "C40-not-a-manifest-store": "not a C2PA manifest store",
    "C50-truncated": "outside its parent", "C51-trailing-bytes": "not a whole box", "C52-box-beyond-parent": "outside its parent",
    "C53-nesting-too-deep": "nested more than 8", "C54-too-many-boxes": "more than 10000 boxes",
    "C55-cbor-trailing": "bytes after the CBOR", "C56-cbor-invalid-utf8": "UnicodeDecodeError",
    "C57-cbor-repeated-key": "repeats a key", "C58-cbor-unterminated": "cut off", "C59-json-repeated-key": "repeats a key",
    "C60-png-bad-crc": "CRC does not match", "C61-jpeg-without-eoi": "cut off",
}


def scan(data: bytes):
    return worker.analyse(SCANNERS, data), engine.correlate(worker.analyse(engine.SCANNERS, data))


def rules(report) -> dict[str, str]:
    return {f.rule_id: f.severity.value for f in report.findings}


def high(report) -> set[str]:
    return {f.rule_id for f in report.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)}


@pytest.mark.parametrize("sid", CASES)
def test_every_synthetic_case_meets_its_required_outcome(sid):
    case = CASES[sid]
    reference, unified = scan(case["data"])
    assert outcome(case["cls"], verdicts(unified)["aggregate"]) == "correct"
    assert verdicts(reference)["aggregate"] in ("SUSPICIOUS", "MALICIOUS")  # every case has an attachment
    assert high(reference) <= high(unified) | {"PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD"}  # replaced by the chain rule
    found = rules(unified)
    if case["cls"] == "c2pa-benign":
        [verified] = [f for f in unified.findings if f.rule_id == VERIFIED]
        assert "whose signature was not validated" in verified.evidence[0]
        assert verified.evidence[-2:] == [ACCOUNTS.format("pdf", "PDF_EMBEDDED_FILE"),
                                          ACCOUNTS.format("yara-x", "PDF_Embedded_File")]
        note = next(f for f in unified.findings if f.rule_id == "ENGINE_CORRELATION")
        assert any(e.startswith("raw pdf:PDF_EMBEDDED_FILE LOW: ") for e in note.evidence)
        assert any(e.startswith("raw yara-x:PDF_Embedded_File LOW: ") for e in note.evidence)
    elif sid in REASONS:
        [unverified] = [f for f in unified.findings if f.rule_id == UNVERIFIED]
        assert any("not verified" in e and REASONS[sid] in e for e in unverified.evidence), unverified.evidence
    else:  # verified manifest, but something else keeps the warning: an action, another attachment, an old revision
        assert VERIFIED not in found and ("PDF_EMBEDDED_FILE" in found or UNVERIFIED in found)


def test_the_presence_of_a_manifest_is_not_its_activation():
    """The same verifiable store: SAFE alone, MALICIOUS when an automatic chain exports or launches it."""
    assert verdicts(scan(CASES["C01-cbor-only"]["data"])[1])["aggregate"] == "SAFE"
    for sid in ("C70-auto-js-exports-manifest", "C71-auto-launch-manifest"):
        unified = scan(CASES[sid]["data"])[1]
        assert rules(unified)["ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT"] == "HIGH"
        assert verdicts(unified)["aggregate"] == "MALICIOUS"


def verify(*assertions: bytes, title: str = "t") -> str:
    return c2pa.verify(store(*assertions, title=title))


def test_a_minimal_store_is_described_and_never_called_authentic():
    what = verify(embedded("c2pa.icon", "image/svg+xml", ICON), embedded("c2pa.thumbnail.claim.jpeg", "image/jpeg", jpeg()))
    assert "1 manifest(s)" in what and "c2pa.icon static SVG" in what and "c2pa.thumbnail.claim.jpeg JPEG" in what
    assert what.startswith("a C2PA manifest store (Content Credentials) whose signature was not validated")


@pytest.mark.parametrize("text", [
    "plain title", "tab\tand\nline\r\nbreaks", "a < b and c > d", "@#(*)!|$%^`~\"/'+={}[]?/<>,.\\",
    "1' or '1' = '1", "admin'; -- ", "https://example.org/?a=1&online=1", "A" * 10_000, "Hello\\x00World",
])
def test_text_without_markup_or_control_characters_is_data(text):
    verify(title=text)


@pytest.mark.parametrize("text", [
    "<script>alert('xss');</script>", "\"><b>x</b>", "\" onmouseover=\"x\" foo=\"", "javascript:alert('xss');",
    "Back\bSpace", "Vertical\vTab", "Injected\x00Null", "Substitute\x1aChar", "right‮to left", "zero​width",
])
def test_markup_and_control_characters_in_text_are_not_verified(text):
    with pytest.raises(c2pa.NotVerified, match="text with"):
        verify(title=text)


def raw_cbor(payload: bytes) -> bytes:
    return store(superbox(c2(b"cbor"), "c2pa.actions", box(b"cbor", payload)))


@pytest.mark.parametrize("payload", [
    b"\x9f\x01\x02\xff",  # indefinite array
    b"\xbf\x61a\x01\xff",  # indefinite map
    b"\x7f\x62ab\x61c\xff",  # indefinite text, two chunks
    b"\x5f\x42\x00\x01\xff",  # indefinite bytes
    b"\xd8\x20\x63abc",  # a tag
    b"\xf9\x3c\x00", b"\xfa\x3f\x80\x00\x00", b"\xf8\x20",  # half and single floats, simple value 32
])
def test_well_formed_cbor_is_data(payload):
    c2pa.verify(raw_cbor(payload))


@pytest.mark.parametrize("payload, why", [
    (b"\x1c", "reserved CBOR encoding"), (b"\xff", "break code outside"), (b"\xf8\x10", "simple value in a reserved"),
    (b"\x7f\x62on\x65load=\xff", "text with markup"),  # split across chunks: checked as a consumer joins them
    (b"\x7f\x42ab\xff", "malformed indefinite-length"),  # a byte-string chunk in a text string
    (b"\x5b" + b"\xff" * 8, "longer than its box"), (b"\x9b" + b"\xff" * 8, "cut off"),  # 2**64 - 1 items, read one by one
    (b"\x81" * 70 + b"\x00", "nesting deeper than 64"), (cbor(list(range(100_001))), "more than 100000 CBOR items"),
    (cbor("x" * ((1 << 20) + 1)), "characters of text"),
], ids=lambda v: v if isinstance(v, str) else f"{len(v)} bytes")  # test IDs go into an environment variable
def test_cbor_outside_the_limits_or_rules_is_not_verified(payload, why):
    with pytest.raises(c2pa.NotVerified, match=why):
        c2pa.verify(raw_cbor(payload))


@pytest.mark.parametrize("name, verified", [
    ("Content Credentials", True), ("manifest.c2pa", True), ("MANIFEST.C2PA", True), ("Content Credentials.html", False),
    ("manifest.c2pa.exe", False), ("manifest.svg", False), ("Content‮Credentials", False),
])
def test_the_name_must_not_open_it_as_something_else(name, verified):
    from pypdf import PdfWriter
    import io
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.add_attachment(name, store())  # pypdf writes the name as /F and /UF
    out = io.BytesIO()
    writer.write(out)
    assert (VERIFIED in rules(scan(out.getvalue())[1])) is verified


@pytest.mark.parametrize("picture, why", [
    (jpeg(), ""), (png(), ""), (jpeg()[:-2], "cut off"), (jpeg(after=b"x"), "after its end"),
    (png()[:-1], "cut off"), (png(after=b"x"), "after IEND"), (png(bad_crc=True), "CRC"),
    (b"\xff\xd8\xff\xd9", "without image data"),
])
def test_pictures_are_checked_by_structure(picture, why):
    problem = c2pa.jpeg_problem(picture) if picture.startswith(b"\xff\xd8") else c2pa.png_problem(picture)
    assert (why in problem and problem) if why else problem == ""


def test_an_svg_value_that_escapes_or_names_another_scheme_is_not_static():
    for value in ("url(#g)", "rgb(1,2,3)", "matrix(1 0 0 1 0 0)"):
        verify(embedded("c2pa.icon", "image/svg+xml", f'<svg {NS}><path d="M0 0" fill="{value}"/></svg>'.encode()))
    for value in ("url(https://example.invalid/p#g)", "u\\72l(x)", "expression(alert(1))", "x:y"):
        with pytest.raises(c2pa.NotVerified, match="can refer outside"):
            verify(embedded("c2pa.icon", "image/svg+xml", f'<svg {NS}><path d="M0 0" fill="{value}"/></svg>'.encode()))


def test_a_pdf_with_a_store_is_scanned_as_before_by_the_reference_engine():
    reference = worker.analyse(SCANNERS, c2pa_pdf(store(assertion("c2pa.ingredient", {"relationship": "parentOf"}))))
    assert rules(reference) == {"PDF_EMBEDDED_FILE": "LOW", "PDF_Embedded_File": "LOW"}
