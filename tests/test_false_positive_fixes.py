"""Regression for the benign-corpus false positives (docs/evidence/benign-corpus): the unified
engine supersedes a reference finding only with complete evidence, and keeps it otherwise. Every
fixture is inert: synthetic packages and PDFs; the macro-library member is a placeholder string."""

import io
import zipfile
from pathlib import Path

import pytest
from pypdf import PdfWriter
from pypdf.actions import JavaScript

from app import engine, worker
from app.engine.correlate import finding as engine_finding
from app.models import Finding, ScannerStatus, Severity, WorkerReport
from app.scanners import SCANNERS
from evaluation.cases import verdicts
from tests import custom_fixtures as fx

CORPUS = Path(__file__).resolve().parent.parent / "evaluation/benign_corpus/files"
PICTURE = '<w:p><w:r><w:drawing><a:blip r:link="rId9"/></w:drawing></w:r></w:p>'


def both(data: bytes) -> tuple[dict, dict]:
    """(reference, unified): verdict and rule -> severity."""
    out = []
    for report in (worker.analyse(SCANNERS, data), engine.correlate(worker.analyse(engine.SCANNERS, data))):
        out.append({"verdict": verdicts(report)["aggregate"], **{f.rule_id: f.severity.value for f in report.findings}})
    return out[0], out[1]


# ---------------------------------------------------------------- the benign corpus

@pytest.mark.parametrize("name, superseded, by", [
    ("docx-04-word-linked-picture.docx", "OFFICE_EXTERNAL_NETWORK_PATH", "ENGINE_OFFICE_LOCAL_FILE_TARGETS"),
    ("xlsx-04-excel-external-workbook-link.xlsx", "OFFICE_EXTERNAL_NETWORK_PATH", "ENGINE_OFFICE_LOCAL_FILE_TARGETS"),
    ("pdf-07-libreoffice-hybrid.pdf", "PDF_EMBEDDED_FILE", "ENGINE_PDF_ATTACHMENTS_VERIFIED"),
])
def test_benign_corpus_false_positives_are_superseded(name, superseded, by):
    reference, unified = both((CORPUS / name).read_bytes())
    assert reference["verdict"] == "SUSPICIOUS" and superseded in reference
    assert unified["verdict"] == "SAFE" and superseded not in unified and unified[by] == "INFO"


def test_a_local_template_is_lowered_but_not_cleared():
    reference, unified = both((CORPUS / "docx-05-word-custom-template.docx").read_bytes())
    assert reference["OFFICE_EXTERNAL_AUTOLOAD"] == "MEDIUM"
    assert unified["ENGINE_OFFICE_LOCAL_TEMPLATE"] == "LOW" and unified["verdict"] == "SUSPICIOUS"
    assert "OFFICE_EXTERNAL_AUTOLOAD" not in unified and "ENGINE_OFFICE_EXTERNAL_ON_OPEN" not in unified


# ---------------------------------------------------------------- Office: what is not superseded

@pytest.mark.parametrize("target", [
    r"\\server\share\x.png", "file://server/share/x.png", "file:////server/share/x.png", "file://C:/x.png",
    "file:///C|/x.png", "file:///%5C%5Cserver%5Cshare%5Cx.png",
])
def test_a_picture_on_a_host_or_an_ambiguous_path_keeps_the_network_path_finding(target):
    data = fx.linked_docx(body=PICTURE, main_rels=(("rId9", f"{fx.REL}/image", target, "External"),))
    _, unified = both(data)
    assert unified["OFFICE_EXTERNAL_NETWORK_PATH"] == "MEDIUM" and unified["verdict"] == "SUSPICIOUS"


def test_one_remote_target_among_local_ones_keeps_the_finding():
    data = fx.linked_docx(body=PICTURE + PICTURE.replace("rId9", "rId10"), main_rels=(
        ("rId9", f"{fx.REL}/image", r"file:///C:\pics\a.png", "External"),
        ("rId10", f"{fx.REL}/image", r"\\server\share\b.png", "External")))
    _, unified = both(data)
    assert unified["OFFICE_EXTERNAL_NETWORK_PATH"] == "MEDIUM" and "ENGINE_OFFICE_LOCAL_FILE_TARGETS" not in unified


def test_a_file_hyperlink_to_a_local_program_keeps_the_finding():
    # A click on it can start a program: only targets loaded as data are superseded.
    data = fx.office_package("docx", main_rels=(
        ("rId9", f"{fx.REL}/hyperlink", "file:///C:/Windows/System32/calc.exe", "External"),))
    _, unified = both(data)
    assert unified["OFFICE_EXTERNAL_NETWORK_PATH"] == "MEDIUM"


@pytest.mark.parametrize("body", [
    '<w:p><w:hyperlink r:id="rId9"><w:r><w:t>x</w:t></w:r></w:hyperlink></w:p>',  # an image relationship used as a link
    PICTURE + '<w:p><w:hyperlink r:id="rId9"/></w:p>',  # shown and linked: the link is not data
    "<w:p/>",  # referenced by nothing: its use is not established
])
def test_a_local_target_not_used_only_as_data_keeps_the_finding(body):
    data = fx.linked_docx(body=body, main_rels=(
        ("rId9", f"{fx.REL}/image", "file:///C:/Windows/System32/calc.exe", "External"),))
    _, unified = both(data)
    assert unified["OFFICE_EXTERNAL_NETWORK_PATH"] == "MEDIUM" and "ENGINE_OFFICE_LOCAL_FILE_TARGETS" not in unified


def test_a_package_with_duplicate_members_supersedes_nothing():
    files = fx.office_parts("docx", main_rels=(("rId9", f"{fx.REL}/image", "file:///C:/a.png", "External"),),
                            main_xml=None)
    buf = io.BytesIO(fx.zip_parts(files))
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(buf, "a") as z:
        z.writestr("word/document.xml", "<duplicate/>")
    reference, unified = both(buf.getvalue())
    assert "OFFICE_ZIP_DUPLICATE_ENTRY" in reference
    assert "ENGINE_OFFICE_LOCAL_FILE_TARGETS" not in unified and unified["OFFICE_EXTERNAL_NETWORK_PATH"] == "MEDIUM"


@pytest.mark.parametrize("target, settings", [
    ("https://templates.example.invalid/t.dotm", '<w:attachedTemplate r:id="rId1"/>'),  # remote: merged, MEDIUM
    (r"file:///C:\Templates\t.dotx", ""),  # local but nothing attaches it: not established
])
def test_templates_not_shown_local_and_used_stay_medium(target, settings):
    data = fx.linked_docx(settings=settings, settings_rels=(("rId1", f"{fx.REL}/attachedTemplate", target, "External"),))
    reference, unified = both(data)
    assert reference["OFFICE_EXTERNAL_AUTOLOAD"] == "MEDIUM"
    assert "MEDIUM" in (unified.get("OFFICE_EXTERNAL_AUTOLOAD"), unified.get("ENGINE_OFFICE_EXTERNAL_ON_OPEN"))
    assert "ENGINE_OFFICE_LOCAL_TEMPLATE" not in unified


# ---------------------------------------------------------------- PDF attachments

NS = {"office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
      "script": "urn:oasis:names:tc:opendocument:xmlns:script:1.0",
      "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
      "draw": "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0",
      "form": "urn:oasis:names:tc:opendocument:xmlns:form:1.0",
      "manifest": "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0",
      "xlink": "http://www.w3.org/1999/xlink"}
XMLNS = " ".join(f'xmlns:{p}="{u}"' for p, u in NS.items())


def odf(kind: str = "text", content: str = "<office:body/>", extra: dict | None = None, encoding: str = "utf-8",
        manifest: str = "") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), f"application/vnd.oasis.opendocument.{kind}")  # stored, first
        z.writestr("content.xml", f'<?xml version="1.0" encoding="{encoding}"?><office:document-content {XMLNS}>'
                                  f"{content}</office:document-content>".encode(encoding), zipfile.ZIP_DEFLATED)
        z.writestr("META-INF/manifest.xml", f"<manifest:manifest {XMLNS}>{manifest}</manifest:manifest>",
                   zipfile.ZIP_DEFLATED)
        for name, text in (extra or {}).items():
            z.writestr(name, text, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def pdf_with(name: str, data: bytes, js: str | None = None, more: int = 0) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.add_attachment(name, data)
    for i in range(more):
        writer.add_attachment(f"{i}-{name}", data)
    if js:
        writer.add_open_action(JavaScript(js))  # what add_js did; add_js is gone in pypdf 7
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_an_odf_attachment_without_code_is_verified():
    reference, unified = both(pdf_with("plan.odt", odf()))
    assert reference["verdict"] == "SUSPICIOUS" and unified["verdict"] == "SAFE"
    assert unified["ENGINE_PDF_ATTACHMENTS_VERIFIED"] == "INFO"


def test_a_passive_hyperlink_is_allowed_and_counted():
    data = pdf_with("plan.odt", odf(content='<text:p><text:a xlink:href="https://www.example.org/">x</text:a>'
                                            '<text:a xlink:href="mailto:a@example.org">y</text:a></text:p>'))
    report = engine.correlate(worker.analyse(engine.SCANNERS, data))
    [verified] = [f for f in report.findings if f.rule_id == "ENGINE_PDF_ATTACHMENTS_VERIFIED"]
    assert "2 passive hyperlink(s)" in " ".join(verified.evidence)


PREFIXED = ('<o:event-listeners xmlns:o="urn:oasis:names:tc:opendocument:xmlns:office:1.0">'
            '<s:event-listener xmlns:s="urn:oasis:names:tc:opendocument:xmlns:script:1.0"/></o:event-listeners>')


@pytest.mark.parametrize("name, data, js", [
    ("plan.exe", odf(), None),  # the name a reader saves it under is a program
    ("plan.exe\x00.odt", odf(), None),  # a reader that stops at NUL saves it as plan.exe
    ("plan\u202etdo.odt", odf(), None),  # a bidirectional override changes how the name reads
    ("plan.odt", odf("spreadsheet"), None),  # extension of another type
    ("plan.odt", odf(extra={"Basic/Standard/Module1.xml": "inert placeholder"}), None),  # a macro library part
    ("plan.odt", odf(content='<office:event-listeners><script:event-listener/></office:event-listeners>'), None),
    ("plan.odt", odf(content=PREFIXED), None),  # the same under other prefixes: matched by namespace, not text
    ("plan.odt", odf(content='<office:event-listeners/>', encoding="utf-16"), None),  # not visible as bytes
    ("plan.odt", odf(content='<text:p><text:script script:language="JavaScript">inert</text:script></text:p>'), None),
    ("plan.odt", odf(content='<office:scripts><office:script script:language="ooo:Basic"/></office:scripts>'), None),
    ("plan.odt", odf(content='<draw:applet draw:code="Inert.class"/>'), None),
    ("plan.odt", odf(content='<draw:object-ole><office:binary-data>AAAA</office:binary-data></draw:object-ole>'), None),
    ("plan.odt", odf(content='<draw:floating-frame xlink:href="https://example.invalid/"/>'), None),
    ("plan.odt", odf(content='<draw:image xlink:href="file://server/share/x.png"/>'), None),
    ("plan.odt", odf(content='<draw:image xlink:href="https://beacon.example.invalid/x.png"/>'), None),  # on open
    ("plan.odt", odf(content='<draw:image xlink:href="./../x.png"/>'), None),  # out of the package
    ("plan.odt", odf(content='<draw:image xlink:href="Pictures/missing.png"/>'), None),  # not a part of it
    ("plan.odt", odf(content='<text:p xml:base="https://example.invalid/"><draw:image xlink:href="Pictures/a.png"/>'
                             '</text:p>', extra={"Pictures/a.png": b"\x89PNG\r\n\x1a\n"}), None),
    ("plan.odt", odf(content='<form:button form:image-data="https://example.invalid/b.png"/>'), None),
    ("plan.odt", odf(content='<text:a xlink:href="file:///C:/Windows/System32/calc.exe">x</text:a>'), None),
    ("plan.odt", odf(content='<text:a xlink:href="vnd.sun.star.script:Inert?language=Basic">x</text:a>'), None),
    ("plan.odt", odf(manifest="<manifest:file-entry><manifest:encryption-data/></manifest:file-entry>"), None),
    ("plan.odt", odf(extra={"Pictures/a.png": b"<svg/> not a PNG"}), None),
    ("plan.odt", odf() + b"trailing data", None),
    ("plan.odt", b"plain text, not an OpenDocument package", None),
    ("plan.odt", odf(), "app.alert('inert');"),  # document JavaScript could export it
])
def test_other_attachments_stay_flagged(name, data, js):
    _, unified = both(pdf_with(name, data, js))
    assert unified["verdict"] in ("SUSPICIOUS", "MALICIOUS") and "ENGINE_PDF_ATTACHMENTS_VERIFIED" not in unified


def test_an_odf_with_a_duplicate_member_is_not_verified():
    buf = io.BytesIO(odf())
    with pytest.warns(UserWarning, match="Duplicate name"), zipfile.ZipFile(buf, "a") as z:
        z.writestr("content.xml", "<office:document-content/>")
    _, unified = both(pdf_with("plan.odt", buf.getvalue()))
    assert "ENGINE_PDF_ATTACHMENTS_VERIFIED" not in unified and unified["verdict"] == "SUSPICIOUS"


@pytest.mark.parametrize("extra", [
    b"\n% /EmbeddedFile outside every object\n",
    # an object no cross-reference table points to: only a repairing reader would find it
    b"\n40 0 obj\n<< /Type /Filespec /F (x.exe) /EF << /F 41 0 R >> >>\nendobj\n",
])
def test_content_outside_the_parsed_objects_supersedes_nothing(extra):
    _, unified = both(pdf_with("plan.odt", odf()) + extra)
    assert unified["PDF_EMBEDDED_FILE"] == "LOW" and unified["ENGINE_PDF_ATTACHMENTS_INCOMPLETE"] == "INFO"


def test_more_attachments_than_the_decode_bound_supersede_nothing(monkeypatch):
    monkeypatch.setattr("app.engine.pdf_attachments.MAX_FILES", 2)
    _, unified = both(pdf_with("plan.odt", odf(), more=2))
    assert unified["PDF_EMBEDDED_FILE"] == "LOW" and unified["ENGINE_PDF_ATTACHMENTS_INCOMPLETE"] == "INFO"


# ---------------------------------------------------------------- correlation bounds

def test_a_superseding_rule_does_not_lower_a_finding_above_its_ceiling():
    # The reference scanner rated the attachment finding higher than the engine's examination
    # was validated on: it saw something that examination does not model, so the finding stands.
    verified = engine_finding(
        "ENGINE_PDF_ATTACHMENTS_VERIFIED", Severity.INFO, "x",
        evidence=["accounts for pdf:PDF_EMBEDDED_FILE"])
    report = WorkerReport(
        scanners=[ScannerStatus(name="pdf", status="completed"), ScannerStatus(name="pdf-chains", status="completed")],
        findings=[Finding(scanner="pdf", category="pdf-embedded-file", severity=Severity.MEDIUM,
                          description="x", rule_id="PDF_EMBEDDED_FILE"), verified])
    assert "PDF_EMBEDDED_FILE" in {f.rule_id for f in engine.correlate(report).findings}
    low = report.model_copy(update={"findings": [report.findings[0].model_copy(update={"severity": Severity.LOW}),
                                                 verified]})
    assert "PDF_EMBEDDED_FILE" not in {f.rule_id for f in engine.correlate(low).findings}
