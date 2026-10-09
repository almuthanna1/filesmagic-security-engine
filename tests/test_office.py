"""Office scanner tests.

All inputs are inert synthetic fixtures built by tests/office_fixtures.py. OLE files
are real compound files parsed by the real olefile/msoffcrypto/oleobj code; only the
olevba macro analysis is replaced by a fake, because a valid compressed VBA project
cannot be built without real macro tooling.
"""

import io
import warnings
import zipfile

import pytest
from fastapi.testclient import TestClient

from app import main
from app.models import Severity, Verdict
from app.scanners import office
from app.scanners.office import OfficeScanError, OfficeScanner
from app.scanners.yarax import YaraXScanner
from tests.office_fixtures import make_ole, make_ooxml, ole10native, rels, word_body, word_document_stream

EQUATION_CLSID = "0002CE02-0000-0000-C000-000000000046"
RANK = {s: i for i, s in enumerate(Severity)}  # Severity is a str enum; max() would sort by name


def worst(findings):
    return max((f.severity for f in findings), key=RANK.__getitem__)


def scan(data):
    return OfficeScanner().scan("f", data)


def rule_ids(findings):
    return sorted(f.rule_id for f in findings)


def field(instr_runs):
    runs = "".join(f"<w:r><w:instrText>{t}</w:instrText></w:r>" for t in instr_runs)
    return word_body(
        f'<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>{runs}<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>'
    )


class FakeVBAParser:
    """Stands in for olevba.VBA_Parser; returns canned analyze_macros() results."""

    def __init__(self, results=(), macros=True, raises=None):
        self.results, self.macros, self.raises, self.closed = list(results), macros, raises, False

    def __call__(self, label, data):
        if self.raises:
            raise self.raises
        return self

    def detect_macros(self):
        return self.macros

    def analyze_macros(self):
        return self.results

    def close(self):
        self.closed = True


def fake_vba(monkeypatch, **kwargs):
    fake = FakeVBAParser(**kwargs)
    monkeypatch.setattr(office, "VBA_Parser", fake)
    return fake


DOCM = make_ooxml({"word/vbaProject.bin": make_ole({"VBA/dir": b"x"})})
AUTOEXEC = ("AutoExec", "Document_Open", "Runs when the Word document is opened")
SHELL = ("Suspicious", "Shell", "May run an executable file or a system command")
OPEN = ("Suspicious", "Open", "May open a file")


# --------------------------------------------------------------------- format identification


@pytest.mark.parametrize(
    "data",
    [
        b"hello world",
        b"%PDF-1.7\n%%EOF",
        b"\x89PNG\r\n\x1a\n",
        b"",
    ],
)
def test_non_office_files_are_not_applicable(data):
    assert scan(data) is None


def test_plain_zip_without_content_types_is_not_applicable():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes.txt", "hello")
    assert scan(buf.getvalue()) is None


def test_non_office_ole_file_is_not_applicable():
    assert scan(make_ole({"SummaryInformation": b"x", "Property": b"y"})) is None  # e.g. MSI, .msg


def test_extension_is_ignored():
    assert OfficeScanner().scan("report.docx", b"plain text") is None
    assert OfficeScanner().scan("image.png", make_ooxml({})) == []


# --------------------------------------------------------------------- benign documents


@pytest.mark.parametrize("kind", ["word", "xl", "ppt"])
def test_benign_ooxml_has_no_findings(kind):
    assert scan(make_ooxml({}, kind=kind)) == []


def test_benign_legacy_doc_has_no_findings():
    assert scan(make_ole({"WordDocument": word_document_stream(), "1Table": b"x"})) == []


def test_ordinary_hyperlink_and_chart_embedding_are_not_flagged():
    doc = make_ooxml({
        "word/_rels/document.xml.rels": rels(("hyperlink", "https://example.test/page", True)),
        "word/embeddings/Microsoft_Excel_Worksheet.xlsx": b"PK\x03\x04 chart data",
    })
    assert scan(doc) == []


# --------------------------------------------------------------------- macros


def test_macro_project_presence_is_low(monkeypatch):
    fake = fake_vba(monkeypatch, results=[])
    findings = scan(DOCM)
    assert rule_ids(findings) == ["OFFICE_MACROS_PRESENT"]
    assert findings[0].severity == Severity.LOW
    assert fake.closed


def test_autoexec_is_medium(monkeypatch):
    fake_vba(monkeypatch, results=[AUTOEXEC])
    findings = {f.rule_id: f for f in scan(DOCM)}
    assert findings["OFFICE_MACRO_AUTOEXEC"].severity == Severity.MEDIUM
    assert "Document_Open" in findings["OFFICE_MACRO_AUTOEXEC"].description


def test_dangerous_capability_without_autoexec_is_medium(monkeypatch):
    fake_vba(monkeypatch, results=[SHELL])
    assert worst(scan(DOCM)) == Severity.MEDIUM


def test_weak_keywords_are_low(monkeypatch):
    fake_vba(monkeypatch, results=[OPEN])
    findings = {f.rule_id: f for f in scan(DOCM)}
    assert findings["OFFICE_MACRO_SUSPICIOUS_KEYWORDS"].severity == Severity.LOW


def test_obfuscated_strings_are_low(monkeypatch):
    fake_vba(monkeypatch, results=[("Base64 String", "aGVsbG8=", "hello")])
    assert "OFFICE_MACRO_OBFUSCATION" in rule_ids(scan(DOCM))


def test_autoexec_plus_command_execution_is_high(monkeypatch):
    fake_vba(monkeypatch, results=[AUTOEXEC, SHELL])
    findings = scan(DOCM)
    assert "OFFICE_MACRO_AUTOEXEC_EXECUTION" in rule_ids(findings)
    assert worst(findings) == Severity.HIGH


def test_vba_stomping_counts_as_strong(monkeypatch):
    stomping = ("Suspicious", "VBA Stomping", "VBA Stomping was detected: the VBA source code and P-code are different")
    fake_vba(monkeypatch, results=[AUTOEXEC, stomping])
    assert "OFFICE_MACRO_AUTOEXEC_EXECUTION" in rule_ids(scan(DOCM))


def test_macro_keywords_are_sanitised(monkeypatch):
    fake_vba(monkeypatch, results=[("AutoExec", "Auto\x00Open\n" + "A" * 200, "x")])
    description = next(f.description for f in scan(DOCM) if f.rule_id == "OFFICE_MACRO_AUTOEXEC")
    assert "\x00" not in description and "\n" not in description and len(description) < 120


def test_unparseable_vba_storage_is_reported_not_passed():
    # Real olevba: a VBA storage without a valid project.
    assert rule_ids(scan(DOCM)) == ["OFFICE_VBA_UNPARSED"]


def test_legacy_doc_macros_use_olevba(monkeypatch):
    fake_vba(monkeypatch, results=[AUTOEXEC])
    doc = make_ole({"WordDocument": word_document_stream(), "Macros/VBA/dir": b"x"})
    assert "OFFICE_MACRO_AUTOEXEC" in rule_ids(scan(doc))


def test_xlm_macrosheet_is_medium():
    findings = scan(make_ooxml({"xl/macrosheets/sheet1.xml": "<xm/>"}, kind="xl"))
    assert rule_ids(findings) == ["OFFICE_XLM_MACROSHEET"]
    assert findings[0].severity == Severity.MEDIUM


def test_vba_parser_failure_raises(monkeypatch):
    fake_vba(monkeypatch, raises=RuntimeError("olevba crashed"))
    with pytest.raises(OfficeScanError, match="olevba crashed"):
        scan(DOCM)


# --------------------------------------------------------------------- external relationships


def doc_with_rel(rel_type, target):
    return make_ooxml({"word/_rels/document.xml.rels": rels((rel_type, target, True))})


@pytest.mark.parametrize(
    "rel_type, target, rule_id, severity",
    [
        ("attachedTemplate", "https://example.test/template.dotm", "OFFICE_EXTERNAL_AUTOLOAD", Severity.MEDIUM),
        ("oleObject", "https://example.test/object", "OFFICE_EXTERNAL_AUTOLOAD", Severity.MEDIUM),
        ("oleObject", "mhtml:https://example.test/page.html!x", "OFFICE_EXTERNAL_DANGEROUS_SCHEME", Severity.HIGH),
        ("oleObject", "https://example.test/page.html!", "OFFICE_EXTERNAL_DANGEROUS_SCHEME", Severity.HIGH),
        ("hyperlink", "ms-msdt:/id PCWDiagnostic", "OFFICE_EXTERNAL_DANGEROUS_SCHEME", Severity.HIGH),
        ("image", "file://server/share/pixel.png", "OFFICE_EXTERNAL_NETWORK_PATH", Severity.MEDIUM),
        ("image", "https://example.test/pixel.png", "OFFICE_EXTERNAL_RESOURCE", Severity.INFO),
    ],
)
def test_external_relationships(rel_type, target, rule_id, severity):
    [f] = scan(doc_with_rel(rel_type, target))
    assert (f.rule_id, f.severity, f.category) == (rule_id, severity, "office-external-relationship")


def test_many_external_relationships_are_aggregated():
    targets = [("image", f"https://example.test/{i}.png", True) for i in range(50)]
    [f] = scan(make_ooxml({"word/_rels/document.xml.rels": rels(*targets)}))
    assert "50 external 'image' relationships" in f.description


def test_relationship_target_is_sanitised_and_truncated():
    [f] = scan(doc_with_rel("attachedTemplate", "https://example.test/" + "a" * 500 + "&#10;x"))
    assert len(f.description) < 250 and "\n" not in f.description


# --------------------------------------------------------------------- embedded objects / ActiveX


def doc_with_embedding(blob):
    return make_ooxml({"word/embeddings/oleObject1.bin": blob})


def test_embedded_package_with_executable_name_is_high():
    [f] = scan(doc_with_embedding(make_ole({"\x01Ole10Native": ole10native("invoice.exe")})))
    assert (f.rule_id, f.severity) == ("OFFICE_PACKAGE_EXECUTABLE", Severity.HIGH)
    assert "invoice.exe" in f.description


def test_embedded_package_with_document_name_is_medium():
    [f] = scan(doc_with_embedding(make_ole({"\x01Ole10Native": ole10native("notes.txt")})))
    assert (f.rule_id, f.severity) == ("OFFICE_PACKAGE_OBJECT", Severity.MEDIUM)


def test_generic_embedded_ole_object_is_low():
    [f] = scan(doc_with_embedding(make_ole({"CONTENTS": b"x"})))
    assert (f.rule_id, f.severity) == ("OFFICE_EMBEDDED_OLE", Severity.LOW)


def test_embedded_non_ole_binary_is_low():
    [f] = scan(doc_with_embedding(b"opaque binary"))
    assert f.rule_id == "OFFICE_EMBEDDED_BINARY"


def test_equation_editor_object_is_high():
    blob = make_ole({"Equation Native": b"x"}, {"": EQUATION_CLSID})
    [f] = scan(doc_with_embedding(blob))
    assert (f.rule_id, f.severity) == ("OFFICE_EQUATION_EDITOR", Severity.HIGH)


def test_legacy_doc_embedded_objects():
    generic = make_ole({"WordDocument": word_document_stream(), "ObjectPool/_1/CONTENTS": b"x"})
    assert rule_ids(scan(generic)) == ["OFFICE_EMBEDDED_OLE"]
    package = make_ole({"WordDocument": word_document_stream(), "ObjectPool/_1/\x01Ole10Native": ole10native("a.hta")})
    assert rule_ids(scan(package)) == ["OFFICE_PACKAGE_EXECUTABLE"]
    equation = make_ole({"WordDocument": word_document_stream(), "ObjectPool/_1/Equation Native": b"x"},
                        {"ObjectPool/_1": EQUATION_CLSID})
    assert rule_ids(scan(equation)) == ["OFFICE_EQUATION_EDITOR"]


def test_activex_parts_are_medium():
    [f] = scan(make_ooxml({"word/activeX/activeX1.xml": "<ax/>", "word/activeX/activeX1.bin": b"x"}))
    assert (f.rule_id, f.severity) == ("OFFICE_ACTIVEX", Severity.MEDIUM)
    assert "2 ActiveX" in f.description


# --------------------------------------------------------------------- DDE


def test_ddeauto_split_across_runs_is_high():
    [f] = scan(make_ooxml({"word/document.xml": field(["DDEAU", "TO calc"])}))
    assert (f.rule_id, f.severity) == ("OFFICE_DDEAUTO_FIELD", Severity.HIGH)


def test_dde_field_is_medium():
    [f] = scan(make_ooxml({"word/document.xml": field(["DDE excel sheet1"])}))
    assert (f.rule_id, f.severity) == ("OFFICE_DDE_FIELD", Severity.MEDIUM)


def test_fldsimple_dde_in_header_is_detected():
    header = word_body('<w:fldSimple w:instr="DDEAUTO x y"/>')
    assert rule_ids(scan(make_ooxml({"word/header1.xml": header}))) == ["OFFICE_DDEAUTO_FIELD"]


def test_ordinary_fields_are_not_dde():
    assert scan(make_ooxml({"word/document.xml": field([" PAGE "])})) == []


@pytest.mark.parametrize("service, severity", [("cmd", Severity.HIGH), ("SomeApp", Severity.MEDIUM)])
def test_excel_dde_link(service, severity):
    link = f'<externalLink xmlns="x"><ddeLink ddeService="{service}" ddeTopic="t"/></externalLink>'
    [f] = scan(make_ooxml({"xl/externalLinks/externalLink1.xml": link}, kind="xl"))
    assert (f.rule_id, f.severity) == ("OFFICE_DDE_LINK", severity)


# --------------------------------------------------------------------- encryption


def test_encrypted_legacy_document_is_medium():
    [f] = scan(make_ole({"WordDocument": word_document_stream(encrypted=True)}))
    assert (f.rule_id, f.severity) == ("OFFICE_ENCRYPTED", Severity.MEDIUM)


def test_encrypted_ooxml_container_is_medium():
    [f] = scan(make_ole({"EncryptionInfo": b"x", "EncryptedPackage": b"y"}))
    assert f.rule_id == "OFFICE_ENCRYPTED"


# --------------------------------------------------------------------- ZIP safety


def zip_with(entries):
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # duplicate-name warning
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in entries:
                zf.writestr(name, content)
    return buf.getvalue()


BASE = [("[Content_Types].xml", "<Types/>"), ("word/document.xml", word_body())]


@pytest.mark.parametrize("name", ["../evil.txt", "word/../../evil.txt", "/etc/evil", "C:/evil.txt"])
def test_path_traversal_member_is_high(name):
    findings = scan(zip_with(BASE + [(name, "x")]))
    assert "OFFICE_ZIP_PATH_TRAVERSAL" in rule_ids(findings)
    assert worst(findings) == Severity.HIGH


def test_duplicate_member_is_medium():
    assert rule_ids(scan(zip_with(BASE + [("word/document.xml", word_body())]))) == ["OFFICE_ZIP_DUPLICATE_ENTRY"]


def test_zip_encrypted_member_is_flagged_and_not_read():
    data = bytearray(zip_with(BASE + [("word/vbaProject.bin", b"not really encrypted")]))
    # zipfile cannot write encrypted members; set the "encrypted" flag (bit 0 of the
    # general-purpose flags, offset 8) in that member's central-directory header.
    name = data.rindex(b"word/vbaProject.bin")  # the central directory comes last
    header = data.rindex(bytes.fromhex("504B0102"), 0, name)
    data[header + 8] |= 0x1
    assert rule_ids(scan(bytes(data))) == ["OFFICE_ZIP_ENCRYPTED_ENTRY"]


def test_non_ole_vba_project_is_unparsed_not_read_as_text():
    doc = make_ooxml({"word/vbaProject.bin": b"Sub AutoOpen() End Sub"})
    assert rule_ids(scan(doc)) == ["OFFICE_VBA_UNPARSED"]


def test_too_many_entries(monkeypatch):
    monkeypatch.setattr(office, "MAX_ZIP_ENTRIES", 5)
    findings = scan(zip_with(BASE + [(f"word/media/{i}.png", "x") for i in range(10)]))
    assert rule_ids(findings) == ["OFFICE_ZIP_TOO_MANY_ENTRIES"]


def test_decompression_bomb_detected_from_declared_sizes(monkeypatch):
    monkeypatch.setattr(office, "MAX_TOTAL_UNCOMPRESSED", 1024 * 1024)  # scaled down to keep the test light
    bomb = zip_with(BASE + [("word/media/big.bin", b"\0" * (5 * 1024 * 1024))])
    assert len(bomb) < 64 * 1024  # 5 MB declared from a few KB
    findings = scan(bomb)
    assert rule_ids(findings) == ["OFFICE_ZIP_DECOMPRESSION_BOMB"]
    assert findings[0].severity == Severity.HIGH


def test_oversized_part_that_must_be_read_fails_closed(monkeypatch):
    monkeypatch.setattr(office, "MAX_MEMBER_BYTES", 100)
    with pytest.raises(OfficeScanError, match="too large"):
        scan(make_ooxml({"word/document.xml": word_body("<w:p/>" * 100)}))


# --------------------------------------------------------------------- malformed input: fail closed


def test_xml_with_dtd_is_rejected():
    evil = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><Relationships>&a;</Relationships>'
    with pytest.raises(OfficeScanError):
        scan(make_ooxml({"word/_rels/document.xml.rels": evil}))


def test_malformed_xml_fails_closed():
    with pytest.raises(OfficeScanError):
        scan(make_ooxml({"word/_rels/document.xml.rels": "<Relationships><unclosed>"}))


def test_corrupt_zip_claiming_to_be_office_fails_closed():
    with pytest.raises(OfficeScanError, match="malformed OOXML"):
        scan(b"PK\x03\x04" + b"\0" * 26 + b"[Content_Types].xml" + b"garbage")


def test_corrupt_ole_fails_closed():
    with pytest.raises(OfficeScanError):
        scan(bytes.fromhex("D0CF11E0A1B11AE1") + b"\xff" * 2000)


# --------------------------------------------------------------------- API + YARA-X interaction

client = TestClient(main.app)


def post(monkeypatch, data, scanners=None):
    monkeypatch.setattr(main, "SCANNERS", scanners or [YaraXScanner(), OfficeScanner()])
    r = client.post("/scan", files={"file": ("upload", data)})
    assert r.status_code == 200
    return r.json()


def test_api_benign_docx_is_safe(monkeypatch):
    body = post(monkeypatch, make_ooxml({}))
    assert body["verdict"] == Verdict.SAFE
    assert body["message"].startswith("Analysed by 2 of 2 scanners.")


def test_api_non_office_file_is_not_failed_by_office_scanner(monkeypatch):
    body = post(monkeypatch, b"plain text")
    assert body["verdict"] == Verdict.SAFE
    assert "(1 not applicable to this file type)" in body["message"]


def test_api_file_no_scanner_handles_is_unable_to_scan(monkeypatch):
    body = post(monkeypatch, b"plain text", scanners=[OfficeScanner()])
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert "None of the configured scanners supports this file type" in body["message"]


def test_api_dangerous_external_relationship_is_malicious(monkeypatch):
    body = post(monkeypatch, doc_with_rel("oleObject", "mhtml:https://example.test/x.html!"))
    assert body["verdict"] == Verdict.MALICIOUS


def test_api_macro_document_is_suspicious_with_both_layers(monkeypatch):
    fake_vba(monkeypatch, results=[AUTOEXEC])
    body = post(monkeypatch, DOCM)
    assert body["verdict"] == Verdict.SUSPICIOUS
    scanners = {f["scanner"] for f in body["findings"]}
    assert scanners == {"yara-x", "office"}  # YARA-X OOXML_VBA_Macros + structural findings


def test_api_autoexec_command_macro_is_malicious(monkeypatch):
    fake_vba(monkeypatch, results=[AUTOEXEC, SHELL])
    assert post(monkeypatch, DOCM)["verdict"] == Verdict.MALICIOUS


def test_api_office_parse_failure_is_unable_to_scan(monkeypatch):
    body = post(monkeypatch, make_ooxml({"word/_rels/document.xml.rels": "<broken"}))
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert body["findings"] == []


def test_api_evidence_wins_over_office_failure(monkeypatch):
    # YARA-X finds a Launch action, Office scanner fails: still MALICIOUS.
    class Broken:
        name = "office"

        def scan(self, filename, data):
            raise RuntimeError("boom")

    body = post(monkeypatch, b"%PDF-1.7 /Launch", scanners=[YaraXScanner(), Broken()])
    assert body["verdict"] == Verdict.MALICIOUS


def test_default_registry_has_both_scanners():
    assert [s.name for s in main.SCANNERS] == ["yara-x", "office"]
