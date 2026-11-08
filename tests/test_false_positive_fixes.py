"""Regression for the benign-corpus false positives (docs/evidence/benign-corpus): the unified
engine supersedes a reference finding only with complete evidence, and keeps it otherwise. Every
fixture is inert: synthetic packages and PDFs; the macro-library member is a placeholder string."""

import io
import zipfile
from pathlib import Path

import pytest
from pypdf import PdfWriter

from app import engine, worker
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

def odf(kind: str = "text", content: str = "<office:body/>", extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), f"application/vnd.oasis.opendocument.{kind}")  # stored, first
        z.writestr("content.xml", f'<office:document-content xmlns:office="o" xmlns:script="s">{content}'
                                  "</office:document-content>", zipfile.ZIP_DEFLATED)
        z.writestr("META-INF/manifest.xml", "<manifest/>", zipfile.ZIP_DEFLATED)
        for name, text in (extra or {}).items():
            z.writestr(name, text, zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def pdf_with(name: str, data: bytes, js: str | None = None) -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(100, 100)
    writer.add_attachment(name, data)
    if js:
        writer.add_js(js)
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()


def test_an_odf_attachment_without_code_is_verified():
    reference, unified = both(pdf_with("plan.odt", odf()))
    assert reference["verdict"] == "SUSPICIOUS" and unified["verdict"] == "SAFE"
    assert unified["ENGINE_PDF_ATTACHMENTS_VERIFIED"] == "INFO"


@pytest.mark.parametrize("name, data, js", [
    ("plan.exe", odf(), None),  # the name a reader saves it under is a program
    ("plan.odt", odf("spreadsheet"), None),  # extension of another type
    ("plan.odt", odf(extra={"Basic/Standard/Module1.xml": "inert placeholder"}), None),  # a macro library part
    ("plan.odt", odf(content='<office:event-listeners><script:event-listener/></office:event-listeners>'), None),
    ("plan.odt", odf(content='<draw:image xlink:href="file://server/share/x.png"/>'), None),
    ("plan.odt", b"plain text, not an OpenDocument package", None),
    ("plan.odt", odf(), "app.alert('inert');"),  # document JavaScript could export it
])
def test_other_attachments_stay_flagged(name, data, js):
    _, unified = both(pdf_with(name, data, js))
    assert unified["verdict"] in ("SUSPICIOUS", "MALICIOUS") and "ENGINE_PDF_ATTACHMENTS_VERIFIED" not in unified


def test_an_embedded_file_token_outside_every_object_supersedes_nothing():
    data = pdf_with("plan.odt", odf()) + b"\n% /EmbeddedFile outside every object\n"
    _, unified = both(data)
    assert unified["PDF_Embedded_File"] == "LOW" and unified["ENGINE_PDF_ATTACHMENTS_INCOMPLETE"] == "INFO"
