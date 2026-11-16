"""Custom detector, Week 2 phase 1: OOXML package foundation and C4-C6."""

import asyncio
import logging
import struct

import pytest
from fastapi.testclient import TestClient

from app import main, worker
from app.models import Severity, Verdict
from app.scanners.custom import CustomScanError, CustomScanner, ooxml_package
from app.scanners.custom.ooxml_package import main_document, open_package, resolve
from app.worker import classify
from tests import custom_fixtures as fx
from tests.office_fixtures import make_ooxml
from tests.scan_client import post_scan

scanner = CustomScanner()
client = TestClient(main.app)
KINDS = ["docx", "xlsx", "pptx"]
MACRO_KINDS = ["docm", "xlsm", "pptm"]
REL = fx.REL


def rules(data: bytes) -> dict:
    return {f.rule_id: f for f in scanner.scan("", data)}


def family(kind: str) -> dict:
    return fx.FAMILIES[kind[:3]]


def main_part(kind: str) -> str:
    return f"{family(kind)['dir']}/{family(kind)['main']}"


def child_part(kind: str) -> str:
    return f"{family(kind)['dir']}/{family(kind)['child'][1]}"


def fails_as(data: bytes, kind: str, match: str | None = None) -> CustomScanError:
    with pytest.raises(CustomScanError, match=match) as e:
        scanner.scan("", data)
    assert classify(e.value) == kind
    return e.value


# ============================================================================= foundation


@pytest.mark.parametrize("source, target, expected", [
    ("word/document.xml", "media/image1.png", "word/media/image1.png"),
    ("", "word/document.xml", "word/document.xml"),  # package relationships: from the root
    ("word/document.xml", "/customXml/item1.xml", "customxml/item1.xml"),  # absolute
    ("word/document.xml", "../customXml/item1.xml", "customxml/item1.xml"),
    ("word/document.xml", "Media/Image%201.PNG", "word/media/image 1.png"),  # case- and %-insensitive
    ("word/document.xml", "../../outside.png", None),  # above the package root
    ("word/document.xml", "https://example.test/x.png", None),  # a URI, not a part name
    ("word/document.xml", "media\\image1.png", None),
])
def test_relationship_targets_resolve_relative_to_their_source(source, target, expected):
    assert resolve(source, target) == expected


def test_open_package_reads_declarations_and_relationships():
    package = open_package(fx.office_package("docx"))
    main = main_document(package)
    assert main.part == "word/document.xml" and main.content_type == fx.MAIN_TYPES["docx"]
    assert package.content_type("word/media/image1.png") == "image/png"  # by Default extension
    assert {r.resolved for r in package.relationships if r.source == "word/document.xml"} == {
        "word/media/image1.png", "word/styles.xml"}


def test_only_opc_packages_are_applicable():
    assert open_package(b"not a zip") is None
    assert open_package(fx.zip_parts({"readme.txt": "a plain ZIP archive"})) is None
    assert scanner.scan("", fx.zip_parts({"readme.txt": "a plain ZIP archive"})) is None
    # A broken ZIP is only treated as Office if it names [Content_Types].xml.
    assert scanner.scan("", fx.zip_parts({"readme.txt": "a plain ZIP archive" * 20})[:60]) is None


# ============================================================================= negative


@pytest.mark.parametrize("kind", KINDS)
def test_normal_documents_produce_no_findings(kind):
    assert scanner.scan("", fx.office_package(kind)) == []


@pytest.mark.parametrize("kind", MACRO_KINDS)
def test_normal_macro_enabled_documents_are_informational_only(kind):
    found = rules(fx.office_package(kind))
    assert set(found) == {"CUSTOM_OFFICE_MACRO_CAPABLE_DECLARATION"}
    assert found["CUSTOM_OFFICE_MACRO_CAPABLE_DECLARATION"].severity == Severity.INFO
    assert "1 macro part(s) present" in found["CUSTOM_OFFICE_MACRO_CAPABLE_DECLARATION"].description


@pytest.mark.parametrize("kind", KINDS)
def test_external_relationships_and_implicit_relationships_are_not_anomalies(kind):
    # The implicit styles/presProps relationship is named by no XML attribute; a hyperlink
    # is external. Neither is a missing target, a dangling reference or a concealed part.
    data = fx.office_package(kind, main_rels=(("rId9", f"{REL}/hyperlink", "https://example.test/", "External"),))
    assert scanner.scan("", data) == []


def test_strict_ooxml_relationship_type_and_namespace_are_understood():
    strict = "http://purl.oclc.org/ooxml/officeDocument/relationships"
    files = fx.office_parts("docx")
    files["_rels/.rels"] = fx.rels_xml(("rId1", f"{strict}/officeDocument", "word/document.xml"))
    files["word/document.xml"] = files["word/document.xml"].replace(f'xmlns:r="{REL}"', f'xmlns:r="{strict}"')
    assert scanner.scan("", fx.zip_parts(files)) == []


def test_the_shared_office_fixture_is_a_valid_package():
    assert scanner.scan("", make_ooxml({})) == []


# ============================================================================= C4 declarations


@pytest.mark.parametrize("kind", MACRO_KINDS)
def test_macro_free_declaration_with_a_macro_project_is_medium(kind):
    plain = kind[:-1] + "x"
    found = rules(fx.zip_parts(fx.office_parts(kind, main_type=fx.MAIN_TYPES[plain])))
    assert set(found) == {"CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH"}
    f = found["CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH"]
    assert f.severity == Severity.MEDIUM and f.scanner == "custom" and f.category == "office-declaration"
    assert "vbaProject.bin" in f.description and "relationship 'rId3' of type vbaProject" in f.description
    assert "Location: [Content_Types].xml; _rels/.rels." in f.description
    assert "not proof that the file is malicious" in f.description


def test_excel_macro_sheet_in_a_macro_free_workbook_is_a_mismatch():
    found = rules(fx.office_package("xlsx", parts={"xl/macrosheets/sheet1.xml": "<xm/>"}))
    assert "'xl/macrosheets/sheet1.xml'" in found["CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH"].description


@pytest.mark.parametrize("kind, declared", [("docx", "xlsx"), ("xlsx", "pptx"), ("pptx", "docx")])
def test_main_type_of_another_family_is_a_family_mismatch(kind, declared):
    found = rules(fx.office_package(kind, main_type=fx.MAIN_TYPES[declared]))
    assert set(found) == {"CUSTOM_OFFICE_FAMILY_MISMATCH"}
    assert found["CUSTOM_OFFICE_FAMILY_MISMATCH"].severity == Severity.LOW


@pytest.mark.parametrize("kind", KINDS)
def test_generic_main_content_type_is_a_family_mismatch(kind):
    f = rules(fx.office_package(kind, main_type="application/xml"))["CUSTOM_OFFICE_FAMILY_MISMATCH"]
    assert f"main part '{main_part(kind)}' is declared as 'application/xml'" in f.description


def test_second_main_document_of_another_family_is_a_family_mismatch():
    found = rules(fx.office_package("docx", overrides={"xl/workbook.xml": fx.MAIN_TYPES["xlsx"]},
                                    parts={"xl/workbook.xml": "<workbook/>"}))
    assert "also declares 'xl/workbook.xml' as a Excel main document" in found["CUSTOM_OFFICE_FAMILY_MISMATCH"].description
    assert found["CUSTOM_OFFICE_UNREACHABLE_PARTS"].severity == Severity.INFO  # nothing leads to it


def test_valid_main_part_outside_its_usual_directory_is_informational():
    files = {name.replace("word/", "content/"): value.replace("word/", "content/") if isinstance(value, str) else value
             for name, value in fx.office_parts("docx").items()}
    found = rules(fx.zip_parts(files))
    assert set(found) == {"CUSTOM_OFFICE_UNCONVENTIONAL_MAIN_PART"}
    assert found["CUSTOM_OFFICE_UNCONVENTIONAL_MAIN_PART"].severity == Severity.INFO


def test_two_main_document_relationships_are_ambiguous():
    files = fx.office_parts("docx")
    files["_rels/.rels"] = fx.rels_xml(("rId1", f"{REL}/officeDocument", "word/document.xml"),
                                       ("rId2", f"{REL}/officeDocument", "word/styles.xml"))
    f = rules(fx.zip_parts(files))["CUSTOM_OFFICE_AMBIGUOUS_MAIN_DOCUMENT"]
    assert f.severity == Severity.LOW and "'rId2' -> 'word/styles.xml'" in f.description


def test_part_without_a_content_type_is_low():
    data = fx.office_package("docx", parts={"word/notes.dat": b"inert"},
                             main_rels=(("rId8", f"{REL}/customData", "notes.dat"),))  # reachable, undeclared
    found = rules(data)
    assert set(found) == {"CUSTOM_OFFICE_UNDECLARED_PARTS"}
    assert "no content type: 'word/notes.dat'" in found["CUSTOM_OFFICE_UNDECLARED_PARTS"].description


def test_conflicting_content_type_declarations_are_low():
    files = fx.office_parts("docx")
    files["[Content_Types].xml"] = files["[Content_Types].xml"].replace(
        "</Types>", '<Default Extension="png" ContentType="application/x-msdownload"/></Types>')
    f = rules(fx.zip_parts(files))["CUSTOM_OFFICE_UNDECLARED_PARTS"]
    assert "conflicting declarations for Default 'png'" in f.description


def test_override_for_a_missing_part_is_informational():
    found = rules(fx.office_package("pptx", overrides={"ppt/slides/slide9.xml": "application/xml"}))
    assert set(found) == {"CUSTOM_OFFICE_STALE_DECLARATIONS"}


def test_the_filename_extension_is_never_used():
    data = fx.office_package("docm", main_type=fx.MAIN_TYPES["docx"])
    assert rules(data).keys() == {f.rule_id for f in scanner.scan("harmless.docm", data)}


# ============================================================================= C5 relationship graph


@pytest.mark.parametrize("kind", KINDS)
def test_relationship_to_a_missing_part_is_informational(kind):
    found = rules(fx.office_package(kind, main_rels=(("rId9", f"{REL}/image", "media/missing.png"),)))
    assert set(found) == {"CUSTOM_OFFICE_REL_MISSING_TARGET"}
    f = found["CUSTOM_OFFICE_REL_MISSING_TARGET"]
    assert f.severity == Severity.INFO and "'rId9' -> 'media/missing.png'" in f.description
    assert f"{family(kind)['dir']}/_rels/{family(kind)['main']}.rels" in f.description


def test_relationship_outside_the_package_is_reported_as_not_a_part_name():
    f = rules(fx.office_package("docx", main_rels=(("rId9", f"{REL}/image", "../../outside.png"),)))[
        "CUSTOM_OFFICE_REL_MISSING_TARGET"]
    assert "(not a part name in the package)" in f.description


@pytest.mark.parametrize("kind", KINDS)
def test_reference_to_an_undeclared_relationship_is_dangling(kind):
    found = rules(fx.office_package(kind, main_xml=family(kind)["xml"]("rId7")))
    assert set(found) == {"CUSTOM_OFFICE_REL_DANGLING_REFERENCE"}
    assert f"'{main_part(kind)}' references 'rId7'" in found["CUSTOM_OFFICE_REL_DANGLING_REFERENCE"].description


def test_dangling_references_are_found_whatever_the_namespace_prefix():
    xml = family("docx")["xml"]("rId7").replace("xmlns:r=", "xmlns:rel=").replace("r:embed", "rel:embed")
    assert "CUSTOM_OFFICE_REL_DANGLING_REFERENCE" in rules(fx.office_package("docx", main_xml=xml))


def test_duplicate_relationship_id_is_low():
    found = rules(fx.office_package("xlsx", main_rels=(("rId1", f"{REL}/worksheet", "worksheets/sheet1.xml"),)))
    assert set(found) == {"CUSTOM_OFFICE_REL_DUPLICATE_ID"}
    assert "Id 'rId1' declared 2 times" in found["CUSTOM_OFFICE_REL_DUPLICATE_ID"].description


@pytest.mark.parametrize("kind", KINDS)
def test_unreferenced_binary_part_is_concealed(kind):
    payload = f"{family(kind)['dir']}/embeddings/payload.bin"
    found = rules(fx.office_package(kind, parts={payload: b"inert test bytes"},
                                    defaults={"bin": "application/octet-stream"}))
    assert set(found) == {"CUSTOM_OFFICE_CONCEALED_BINARY_PART"}
    f = found["CUSTOM_OFFICE_CONCEALED_BINARY_PART"]
    assert f.severity == Severity.LOW and f"'{payload}' (application/octet-stream, 16 bytes)" in f.description


@pytest.mark.parametrize("parts, note", [
    ({"customXml/item1.xml": "<x/>"}, "'customXml/item1.xml'"),  # leftover XML
    ({"word/_rels/ghost.xml.rels": fx.rels_xml()}, "'word/_rels/ghost.xml.rels'"),  # orphaned relationships
    ({"[trash]/0000.dat": b"old"}, "'[trash]/0000.dat' (Office 2007 trash)"),  # binary, but a known leftover
])
def test_other_unreachable_parts_are_informational(parts, note):
    found = rules(fx.office_package("docx", parts=parts, defaults={"dat": "application/octet-stream"}))
    assert set(found) == {"CUSTOM_OFFICE_UNREACHABLE_PARTS"}
    assert note in found["CUSTOM_OFFICE_UNREACHABLE_PARTS"].description


# ============================================================================= C6 ZIP container


def test_declared_size_beyond_deflate_limits_is_impossible_and_never_decompressed():
    data = fx.patch(fx.office_package("xlsx"), child_part("xlsx"), local={"usize": 50_000_000}, central={"usize": 50_000_000})
    found = rules(data)
    assert found["CUSTOM_OFFICE_ZIP_IMPOSSIBLE_SIZE"].severity == Severity.LOW
    assert found["CUSTOM_OFFICE_ZIP_OVERSIZED_PART"].severity == Severity.INFO
    assert "'xl/worksheets/sheet1.xml' not read: declared size 50000000 bytes" in found[
        "CUSTOM_OFFICE_COVERAGE_LIMITED"].description


def test_stored_entry_with_different_sizes_is_impossible():
    data = fx.zip_parts(fx.office_parts("docx"), method=fx.zipfile.ZIP_STORED)
    data = fx.patch(data, "word/media/image1.png", local={"usize": 33}, central={"usize": 33})
    assert "CUSTOM_OFFICE_ZIP_IMPOSSIBLE_SIZE" in rules(data)


def test_large_highly_compressed_part_is_informational_not_impossible():
    styles = f'<w:styles xmlns:w="{fx.W}">' + "<w:style/>" * 300_000 + "</w:styles>"
    found = rules(fx.office_package("docx", parts={"word/styles.xml": styles}))
    assert set(found) == {"CUSTOM_OFFICE_ZIP_HIGH_RATIO"}
    assert found["CUSTOM_OFFICE_ZIP_HIGH_RATIO"].severity == Severity.INFO


@pytest.mark.parametrize("local, evidence", [
    ({"name": b"word/media/imageX.png"}, "local header names it 'word/media/imageX.png'"),
    ({"method": 0}, "compression method 0 locally, 8 in the directory"),
    ({"csize": 1}, "CRC or sizes differ"),
])
def test_local_header_that_contradicts_the_directory_is_low(local, evidence):
    f = rules(fx.patch(fx.office_package("docx"), "word/media/image1.png", local=local))["CUSTOM_OFFICE_ZIP_HEADER_MISMATCH"]
    assert f.severity == Severity.LOW and evidence in f.description


def test_entries_sharing_compressed_data_overlap():
    data = fx.office_package("docx", parts={"word/media/image2.png": fx.PNG},
                             main_rels=(("rId8", f"{REL}/image", "media/image2.png"),))
    data = fx.patch(data, "word/media/image2.png", central={"offset": fx.local_offset(data, "word/media/image1.png")})
    f = rules(data)["CUSTOM_OFFICE_ZIP_OVERLAPPING_ENTRIES"]
    assert f.severity == Severity.LOW and "overlaps" in f.description


def test_compression_office_cannot_read_is_low_and_not_decompressed():
    data = fx.patch(fx.office_package("docx"), "word/media/image1.png", local={"method": 12}, central={"method": 12})
    f = rules(data)["CUSTOM_OFFICE_ZIP_UNSUPPORTED_METHOD"]
    assert "'word/media/image1.png' uses method 12" in f.description


def test_non_office_opc_package_gets_container_checks_and_says_so():
    xps = fx.zip_parts({
        "[Content_Types].xml": fx.content_types({"FixedDocSeq.fdseq": "application/vnd.ms-package.xps-fixeddocumentsequence+xml"}),
        "_rels/.rels": fx.rels_xml(("rId1", "http://schemas.microsoft.com/xps/2005/06/fixedrepresentation", "FixedDocSeq.fdseq")),
        "FixedDocSeq.fdseq": "<FixedDocumentSequence/>",
    })
    found = rules(xps)
    assert set(found) == {"CUSTOM_OFFICE_COVERAGE_LIMITED"}
    assert "not a Word, Excel or PowerPoint package" in found["CUSTOM_OFFICE_COVERAGE_LIMITED"].description


# ============================================================================= malformed input


def _corrupt_data(data: bytes, name: str) -> bytes:
    offset = fx.local_offset(data, name)
    nlen, elen = struct.unpack_from("<HH", data, offset + 26)
    start = offset + 30 + nlen + elen
    return data[:start] + b"\xff" * 8 + data[start + 8:]


@pytest.mark.parametrize("make", [
    lambda: fx.office_package("docx")[:200],  # truncated: no central directory
    lambda: fx.office_package("docx", parts={"[Content_Types].xml": "<Types><Default"}),
    lambda: fx.office_package("xlsx", parts={"xl/_rels/workbook.xml.rels": "<Relationships><broken"}),
    lambda: fx.office_package("pptx", parts={"_rels/.rels": '<!DOCTYPE r [<!ENTITY e "x">]><Relationships/>'}),
    lambda: _corrupt_data(fx.office_package("docx"), "_rels/.rels"),  # corrupt deflate data
    lambda: fx.patch(fx.office_package("docx"), "word/styles.xml", local={"name": b"word/stylez.xml"}),
])
def test_malformed_container_or_xml_is_malformed_input(make):
    fails_as(make(), "malformed_input")


def test_essential_part_that_cannot_be_read_fails_closed():
    data = fx.patch(fx.office_package("docx"), "_rels/.rels", local={"method": 12}, central={"method": 12})
    fails_as(data, "invalid_structure", "unsupported ZIP compression method 12")


# ============================================================================= resource limits


@pytest.mark.parametrize("limit, value, message", [
    ("MAX_ENTRIES", 3, "more than 3 ZIP entries"),
    ("MAX_RELATIONSHIPS", 1, "more than 1 relationships"),
    ("MAX_XML_PART_BYTES", 50, "exceeds the analysis limit"),
])
def test_limits_on_essential_structure_fail_closed(monkeypatch, limit, value, message):
    monkeypatch.setattr(ooxml_package, limit, value)
    fails_as(fx.office_package("docx"), "invalid_structure", message)


@pytest.mark.parametrize("limit", ["MAX_PART_BYTES", "MAX_READ_BYTES"])
def test_limits_on_content_parts_are_reported_as_coverage(monkeypatch, limit):
    # Below the size of the content parts, above what the essential parts need in total.
    monkeypatch.setattr(ooxml_package, limit, 100 if limit == "MAX_PART_BYTES" else 1500)
    found = rules(fx.office_package("docx"))
    assert "exceeds the analysis limit" in found["CUSTOM_OFFICE_COVERAGE_LIMITED"].description
    assert "CUSTOM_OFFICE_REL_DANGLING_REFERENCE" not in found  # unread, so not judged


# ============================================================================= API and worker


def status(body: dict, name: str = "custom") -> dict:
    return next(s for s in body["scanners"] if s["name"] == name)


@pytest.mark.parametrize("kind", KINDS)
def test_api_normal_documents_are_safe_with_all_four_scanners(kind):
    body = post_scan(client, fx.office_package(kind)).json()
    assert body["verdict"] == Verdict.SAFE and body["complete"]
    assert status(body)["status"] == "completed"
    assert not [f for f in body["findings"] if f["scanner"] == "custom"]


def test_api_reports_c4_with_independent_attribution():
    body = post_scan(client, fx.zip_parts(fx.office_parts("docm", main_type=fx.MAIN_TYPES["docx"]))).json()
    assert body["verdict"] == Verdict.SUSPICIOUS
    custom = {f["rule_id"]: f["severity"] for f in body["findings"] if f["scanner"] == "custom"}
    assert custom == {"CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH": "MEDIUM"}
    assert any(f["scanner"] == "office" for f in body["findings"])  # its own macro findings, separately


def test_api_malformed_package_fails_closed_with_the_custom_reason(caplog):
    data = fx.office_package("xlsx", parts={"xl/_rels/workbook.xml.rels": "<Relationships><broken"})
    with caplog.at_level(logging.INFO, logger="app.main"):
        body = post_scan(client, data, "broken.xlsx").json()
    assert status(body)["status"] == "failed" and status(body)["error_kind"] == "malformed_input"
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    [record] = [r for r in caplog.records if "scanner=custom" in r.getMessage()]
    assert record.levelno == logging.WARNING and "Office ZIP container or XML part is malformed" in record.getMessage()
    assert "broken.xlsx" not in caplog.text


def test_real_isolated_worker_runs_c4_to_c6():
    report = asyncio.run(worker.run(fx.zip_parts(fx.office_parts("pptm", main_type=fx.MAIN_TYPES["pptx"]))))
    assert next(s for s in report.scanners if s.name == "custom").status == "completed"
    assert "CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH" in {f.rule_id for f in report.findings if f.scanner == "custom"}
    assert report.isolation["process"] and report.isolation["audit_hook"]
