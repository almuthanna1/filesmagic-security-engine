"""PDF scanner tests.

All inputs are inert synthetic PDFs from tests/pdf_fixtures.py, parsed by the real pypdf.
JavaScript bodies are harmless one-liners; attachments are short plain text.
"""

import logging

import pytest
from fastapi.testclient import TestClient

from app import main
from app.models import Severity, Verdict
from app.scanners import pdf
from app.scanners.office import OfficeScanner
from app.scanners.pdf import PdfScanError, PdfScanner
from app.scanners.yarax import YaraXScanner
from tests.office_fixtures import make_ooxml
from tests.pdf_fixtures import attachment, encrypted_pdf, js_action, make_pdf, uri_link

RANK = {s: i for i, s in enumerate(Severity)}


def scan(data):
    return PdfScanner().scan("f", data)


def ids(findings):
    return sorted(f.rule_id for f in findings)


def worst(findings):
    return max((f.severity for f in findings), key=RANK.__getitem__)


def link_js(code="app.alert(1);"):
    return make_pdf(page_extra="/Annots [5 0 R]",
                    objects={5: "<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A 6 0 R >>", 6: js_action(code)})


# --------------------------------------------------------------------- recognition


@pytest.mark.parametrize("data", [b"hello world", b"PK\x03\x04", b"\x89PNG\r\n\x1a\n", b"", b"x" * 2000 + b"%PDF-1.7"])
def test_non_pdf_is_not_applicable(data):
    assert scan(data) is None


def test_extension_is_ignored():
    assert PdfScanner().scan("invoice.pdf", b"plain text") is None
    assert PdfScanner().scan("notes.txt", make_pdf()) == []


def test_header_within_first_kilobyte_is_recognised():
    assert ids(scan(make_pdf(header_offset=500))) == ["PDF_STRUCTURE_REPAIRED"]  # offsets are off, pypdf repairs


# --------------------------------------------------------------------- benign


def test_benign_pdf_has_no_findings():
    assert scan(make_pdf()) == []


def test_benign_pdf_with_object_streams_has_no_findings():
    assert scan(make_pdf(compressed={2, 3})) == []


def test_ordinary_goto_open_action_is_not_reported():
    assert scan(make_pdf("/OpenAction [3 0 R /Fit]")) == []


# --------------------------------------------------------------------- JavaScript


def test_javascript_in_link_is_medium_and_not_automatic():
    assert ids(scan(link_js())) == ["PDF_JAVASCRIPT"]


@pytest.mark.parametrize(
    "catalog_extra, page_extra",
    [
        ("/OpenAction 5 0 R", ""),
        ("/Names << /JavaScript << /Names [(init) 5 0 R] >> >>", ""),  # document-level JavaScript
        ("/AA << /WC 5 0 R >>", ""),  # document will-close
        ("", "/AA << /O 5 0 R >>"),  # page open
    ],
)
def test_automatic_javascript(catalog_extra, page_extra):
    findings = scan(make_pdf(catalog_extra, page_extra, objects={5: js_action()}))
    assert ids(findings) == ["PDF_AUTO_JAVASCRIPT", "PDF_JAVASCRIPT"]
    assert worst(findings) == Severity.MEDIUM


def test_form_field_keystroke_javascript_is_not_automatic():
    field = "<< /FT /Tx /T (amount) /AA << /K 6 0 R /F 6 0 R >> >>"
    findings = scan(make_pdf("/AcroForm << /Fields [5 0 R] >>", objects={5: field, 6: js_action("AFNumber_Format(2);")}))
    assert ids(findings) == ["PDF_ACROFORM", "PDF_JAVASCRIPT"]


def test_javascript_hidden_in_compressed_object_stream_is_found():
    data = make_pdf("/OpenAction 5 0 R", objects={5: js_action()}, compressed={1, 5})
    assert b"/JavaScript" not in data and b"/OpenAction" not in data  # invisible to byte matching
    assert ids(scan(data)) == ["PDF_AUTO_JAVASCRIPT", "PDF_JAVASCRIPT"]


def test_javascript_in_stream_is_searched():
    data = make_pdf("/OpenAction 5 0 R",
                    objects={5: "<< /S /JavaScript /JS 6 0 R >>", 6: "stream:var x = 1; util.printf('%45000f', 1);"})
    assert "PDF_JAVASCRIPT_EXPLOIT_API" in ids(scan(data))


@pytest.mark.parametrize("code", ["util.printf(1)", "Collab.getIcon(x)", "this.exportDataObject({cName: 'a', nLaunch: 2})"])
def test_exploit_api_javascript_is_high(code):
    findings = scan(link_js(code))
    assert "PDF_JAVASCRIPT_EXPLOIT_API" in ids(findings)
    assert worst(findings) == Severity.HIGH


def test_exploit_api_description_does_not_echo_script():
    f = next(f for f in scan(link_js("util.printf('" + "A" * 5000 + "')")) if f.rule_id == "PDF_JAVASCRIPT_EXPLOIT_API")
    assert "AAAA" not in f.description and len(f.description) < 200


def test_automatic_javascript_with_attachment_is_high():
    extra, objs = attachment("report.txt")
    objs[7] = js_action("this.exportDataObject({cName: 'f'});")
    findings = scan(make_pdf(extra + " /OpenAction 7 0 R", objects=objs))
    assert "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD" in ids(findings)
    assert worst(findings) == Severity.HIGH


def test_javascript_reached_both_ways_counts_as_automatic():
    # Same action from a link (user) and from /OpenAction (automatic).
    data = make_pdf("/OpenAction 6 0 R", "/Annots [5 0 R]",
                    objects={5: "<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A 6 0 R >>", 6: js_action()})
    assert "PDF_AUTO_JAVASCRIPT" in ids(scan(data))


# --------------------------------------------------------------------- Launch


def test_launch_action_is_high():
    [f] = scan(make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>"))
    assert (f.rule_id, f.severity) == ("PDF_LAUNCH_ACTION", Severity.HIGH)
    assert "calc.exe" in f.description


def test_launch_with_windows_parameters():
    [f] = scan(make_pdf("/OpenAction << /S /Launch /Win << /F (cmd.exe) /P (/c echo) >> >>"))
    assert f.rule_id == "PDF_LAUNCH_ACTION" and "cmd.exe" in f.description


# --------------------------------------------------------------------- attachments


def test_benign_attachment_is_low():
    extra, objs = attachment("notes.txt")
    [f] = scan(make_pdf(extra, objects=objs))
    assert (f.rule_id, f.severity) == ("PDF_EMBEDDED_FILE", Severity.LOW)
    assert "notes.txt" in f.description


@pytest.mark.parametrize(
    "name, mime",
    [("invoice.exe", "/text#2Fplain"), ("macro.docm", "/text#2Fplain"), ("data.bin", "/application#2Fx-msdownload")],
)
def test_executable_or_macro_attachment_is_high(name, mime):
    extra, objs = attachment(name, mime)
    [f] = scan(make_pdf(extra, objects=objs))
    assert (f.rule_id, f.severity) == ("PDF_EMBEDDED_EXECUTABLE", Severity.HIGH)


def test_file_attachment_annotation_is_detected():
    annot = "<< /Type /Annot /Subtype /FileAttachment /Rect [0 0 1 1] /FS << /Type /Filespec /F (a.vbs) /EF << /F 6 0 R >> >> >>"
    data = make_pdf(page_extra="/Annots [5 0 R]", objects={5: annot, 6: "stream:inert"})
    assert ids(scan(data)) == ["PDF_EMBEDDED_EXECUTABLE"]


# --------------------------------------------------------------------- URIs


@pytest.mark.parametrize("uri", ["https://example.test/page", "http://example.test", "mailto:someone@example.test"])
def test_ordinary_links_are_not_reported(uri):
    assert scan(make_pdf(page_extra="/Annots [5 0 R]", objects=uri_link(uri))) == []


@pytest.mark.parametrize(
    "uri, rule_id, severity",
    [
        ("javascript:alert(1)", "PDF_URI_DANGEROUS_SCHEME", Severity.HIGH),
        ("ms-msdt:/id PCWDiagnostic", "PDF_URI_DANGEROUS_SCHEME", Severity.HIGH),
        ("data:text/html,x", "PDF_URI_DANGEROUS_SCHEME", Severity.HIGH),
        ("file://server/share/x", "PDF_URI_NETWORK_PATH", Severity.MEDIUM),
        ("\\\\\\\\server\\\\share", "PDF_URI_NETWORK_PATH", Severity.MEDIUM),
        ("ftp://example.test/file", "PDF_URI_OTHER_SCHEME", Severity.INFO),
    ],
)
def test_uri_schemes(uri, rule_id, severity):
    [f] = scan(make_pdf(page_extra="/Annots [5 0 R]", objects=uri_link(uri)))
    assert (f.rule_id, f.severity) == (rule_id, severity)


def test_uri_target_is_sanitised_and_truncated():
    [f] = scan(make_pdf(page_extra="/Annots [5 0 R]", objects=uri_link("javascript:" + "a" * 3000 + "\\r\\n")))
    assert len(f.description) < 200 and "\r" not in f.description and "\n" not in f.description


def test_many_links_are_aggregated():
    annots = " ".join(f"{n} 0 R" for n in range(5, 25))
    objs = {n: f"<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI (ftp://h/{n}) >> >>" for n in range(5, 25)}
    [f] = scan(make_pdf(page_extra=f"/Annots [{annots}]", objects=objs))
    assert f.description.startswith("20 link(s)")


# --------------------------------------------------------------------- forms


def test_acroform_is_info():
    [f] = scan(make_pdf("/AcroForm << /Fields [] >>"))
    assert (f.rule_id, f.severity) == ("PDF_ACROFORM", Severity.INFO)


def test_xfa_is_low():
    findings = scan(make_pdf("/AcroForm << /Fields [] /XFA 5 0 R >>", objects={5: "stream:<xdp/>"}))
    assert ids(findings) == ["PDF_ACROFORM", "PDF_XFA_FORM"]
    assert worst(findings) == Severity.LOW


# --------------------------------------------------------------------- encryption


def test_password_protected_pdf_is_medium_and_not_inspected():
    [f] = scan(encrypted_pdf("secret"))
    assert (f.rule_id, f.severity) == ("PDF_ENCRYPTED", Severity.MEDIUM)


def test_permissions_only_encryption_is_inspected():
    findings = scan(encrypted_pdf(""))
    assert ids(findings) == ["PDF_AUTO_JAVASCRIPT", "PDF_ENCRYPTED_PERMISSIONS_ONLY", "PDF_JAVASCRIPT"]


# --------------------------------------------------------------------- pathological / malformed


def test_reference_cycle_terminates():
    objs = {5: "<< /S /GoTo /D [3 0 R /Fit] /Next 6 0 R >>", 6: "<< /S /GoTo /D [3 0 R /Fit] /Next 5 0 R >>"}
    assert scan(make_pdf("/OpenAction 5 0 R", objects=objs)) == []


def test_long_reference_chain_is_fine():
    # 500 outline items linked by /Next: deep chains of references are not "nesting".
    objs = {n: f"<< /Title (item) /Dest [3 0 R /Fit] /Next {n + 1} 0 R >>" for n in range(6, 505)}
    objs[505] = "<< /Title (last) /Dest [3 0 R /Fit] >>"
    objs[5] = "<< /Type /Outlines /First 6 0 R /Last 505 0 R >>"
    assert scan(make_pdf("/Outlines 5 0 R", objects=objs)) == []


def test_deeply_nested_direct_objects_fail_closed():
    with pytest.raises(PdfScanError, match="nested deeper"):
        scan(make_pdf("/Foo " + "[" * 100 + "]" * 100))


def test_pathologically_nested_objects_fail_closed():
    with pytest.raises(PdfScanError):
        scan(make_pdf("/Foo " + "[" * 20000 + "]" * 20000))


def test_object_budget_fails_closed(monkeypatch):
    monkeypatch.setattr(pdf, "MAX_OBJECTS", 3)
    with pytest.raises(PdfScanError, match="exceeds"):
        scan(make_pdf())


@pytest.mark.parametrize("data", [b"%PDF-1.7\nnot really a pdf", b"%PDF-1.4\n1 0 obj << /Type /Catalog"])
def test_malformed_pdf_fails_closed(data):
    with pytest.raises(PdfScanError):
        scan(data)


def test_parser_failure_fails_closed(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("pypdf crashed")

    monkeypatch.setattr(pdf, "PdfReader", broken)
    with pytest.raises(PdfScanError, match="pypdf crashed"):
        scan(make_pdf())


def test_repair_log_handler_is_removed_after_scan():
    before = list(logging.getLogger("pypdf").handlers)
    scan(make_pdf(header_offset=10))
    assert logging.getLogger("pypdf").handlers == before


def test_jbig2_decoder_is_disabled():
    assert pdf.PDF_LIMITS["jbig2dec_binary"] is None


# --------------------------------------------------------------------- YARA-X interaction and API

client = TestClient(main.app)


def post(monkeypatch, data, scanners=None):
    monkeypatch.setattr(main, "SCANNERS", scanners or [YaraXScanner(), OfficeScanner(), PdfScanner()])
    r = client.post("/scan", files={"file": ("upload", data)})
    assert r.status_code == 200
    return r.json()


def test_default_registry_has_three_scanners():
    assert [s.name for s in main.SCANNERS] == ["yara-x", "office", "pdf"]


def test_api_benign_pdf_is_safe(monkeypatch):
    body = post(monkeypatch, make_pdf())
    assert body["verdict"] == Verdict.SAFE
    assert body["message"].startswith("Analysed by 2 of 3 scanners (1 not applicable")


def test_api_javascript_pdf_is_suspicious(monkeypatch):
    body = post(monkeypatch, link_js())
    assert body["verdict"] == Verdict.SUSPICIOUS


def test_api_launch_pdf_is_malicious_from_both_layers(monkeypatch):
    body = post(monkeypatch, make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>"))
    assert body["verdict"] == Verdict.MALICIOUS
    assert {f["rule_id"] for f in body["findings"]} == {"PDF_Launch_Action", "PDF_LAUNCH_ACTION"}


def test_api_compressed_javascript_found_only_structurally(monkeypatch):
    body = post(monkeypatch, make_pdf("/OpenAction 5 0 R", objects={5: js_action()}, compressed={1, 5}))
    assert body["verdict"] == Verdict.SUSPICIOUS
    assert {f["scanner"] for f in body["findings"]} == {"pdf"}  # YARA-X sees no raw bytes


def test_api_malformed_pdf_is_unable_to_scan(monkeypatch):
    body = post(monkeypatch, b"%PDF-1.7\nnot really a pdf")
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert "1 of 2 applicable scanners failed" in body["message"]


def test_api_docx_pdf_scanner_not_applicable(monkeypatch):
    body = post(monkeypatch, make_ooxml({}))
    assert body["verdict"] == Verdict.SAFE
    assert "(1 not applicable" in body["message"]


def test_api_text_two_scanners_not_applicable(monkeypatch):
    body = post(monkeypatch, b"plain text")
    assert body["verdict"] == Verdict.SAFE
    assert "Analysed by 1 of 3 scanners (2 not applicable" in body["message"]
