"""Custom detector, Week 1: scanner contract and C1 (PDF name-token obfuscation)."""

import asyncio
import logging

import pytest
from fastapi.testclient import TestClient

from app import main, worker
from app.models import Severity, Verdict
from app.scanners.custom import CustomScanError, CustomScanner, pdf_syntax
from app.scanners.custom.pdf_syntax import decode_name, parse
from app.worker import classify
from tests import custom_fixtures as fx
from tests.office_fixtures import make_ooxml
from tests.pdf_fixtures import encrypted_pdf
from tests.scan_client import post_scan

scanner = CustomScanner()
client = TestClient(main.app)


def rules(data: bytes) -> dict[str, object]:
    return {f.rule_id: f for f in scanner.scan("", data)}


# ----------------------------------------------------------------------------- name decoding


@pytest.mark.parametrize("raw, decoded, unnecessary", [
    (b"JavaScript", b"JavaScript", 0),
    (b"J#61vaScript", b"JavaScript", 1),  # 'a' never needs an escape
    (b"#4A#53", b"JS", 2),
    (b"Arial#20Bold", b"Arial Bold", 0),  # space: escape required
    (b"text#2Fplain", b"text/plain", 0),  # delimiter: escape required
    (b"A#23B", b"A#B", 0),  # '#' itself: escape required
    (b"caf#E9", b"caf\xe9", 0),  # outside "!" to "~": escape required
    (b"bad#zz", b"bad#zz", 0),  # not an escape: kept literally
])
def test_decode_name_separates_necessary_from_unnecessary_escapes(raw, decoded, unnecessary):
    assert decode_name(raw) == (decoded, unnecessary)


def test_strings_and_comments_do_not_desynchronise_the_lexer():
    data = b"(a \\) /X#41 ( nested stream\n ) b) % comment ( stream\n/Re#61l /plain (simple /S#41)"
    names = [(t[1], t[3]) for t in pdf_syntax.tokens(data, file_body=True)]
    # No stream, no error; escaped names keep their context; ordinary names are skipped.
    assert names == [(b"X#41", "string"), (b"Re#61l", ""), (b"S#41", "string")]


def test_stream_inside_a_name_is_not_the_stream_keyword():
    data = b"1 0 obj << /stream\n/A1stream\n/Type /Catalog >>stream\nx\nendstream endobj"
    assert [t[0] for t in pdf_syntax.tokens(data, file_body=True)] == ["stream"]  # only the real one


def test_every_name_can_be_read_from_a_dictionary():
    names = [t[1] for t in pdf_syntax.tokens(b"<< /Type /ObjStm /T (/Image) >>", file_body=False, all_names=True)]
    assert names == [b"Type", b"ObjStm", b"T"]  # a name inside a string cannot change the stream's type


# ----------------------------------------------------------------------------- contract


def test_only_pdf_is_applicable():
    assert scanner.name == "custom"
    assert scanner.scan("", b"") is None  # the worker's warm-up call
    assert scanner.scan("report.pdf", b"plain text") is None  # the filename is never trusted
    assert scanner.scan("", make_ooxml({})) is None  # OOXML arrives with C4-C10


def test_findings_are_attributed_to_the_custom_scanner():
    findings = scanner.scan("", fx.obfuscated_javascript_pdf())
    assert findings and all(f.scanner == "custom" for f in findings)


# ----------------------------------------------------------------------------- positive


def test_obfuscated_javascript_action_is_reported_with_evidence_and_location():
    found = rules(fx.obfuscated_javascript_pdf())
    assert set(found) == {"CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"}
    f = found["CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"]
    assert f.severity == Severity.MEDIUM and f.category == "pdf-name-obfuscation"
    assert "'/J#61vaScript' decodes to /JavaScript (1x)" in f.description
    assert "'/J#53' decodes to /JS (1x)" in f.description
    assert "Location: object 5 0." in f.description
    assert "not proof that the file is malicious" in f.description


def test_obfuscated_name_inside_an_object_stream_is_found_after_inflating_it():
    f = rules(fx.obfuscated_javascript_pdf(in_object_stream=True))["CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"]
    assert "/J#61vaScript" in f.description
    assert "object stream of object 6 0" in f.description


def test_obfuscated_filter_name_is_decoded_and_its_object_stream_still_inspected():
    found = rules(fx.obfuscated_filter_pdf())
    other = found["CUSTOM_PDF_UNNECESSARY_NAME_ESCAPES"]
    assert other.severity == Severity.INFO and "/Fl#61teDecode' decodes to /FlateDecode" in other.description
    assert "Location: object 6 0." in other.description  # the object stream's own dictionary
    active = found["CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"]
    assert "'/J#53' decodes to /JS" in active.description and "object stream of object 6 0" in active.description


def test_name_hidden_in_a_comment_is_reported_with_its_context():
    f = rules(fx.name_in_comment_pdf())["CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"]
    assert "object 5 0 (inside a comment)" in f.description


def test_repeated_names_are_counted_and_locations_bounded():
    objects = {n: fx.OBFUSCATED_ACTION for n in range(5, 12)}
    f = rules(fx.make_pdf(objects=objects))["CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"]
    assert "(7x)" in f.description
    assert "object 5 0; object 6 0; object 7 0; and 4 more" in f.description


# ----------------------------------------------------------------------------- negative


@pytest.mark.parametrize("make", [
    fx.plain_pdf, fx.plain_javascript_pdf, fx.necessary_escapes_pdf,
    fx.obfuscated_content_stream_pdf,  # by design: content streams hold no object syntax
])
def test_clean_documents_produce_no_findings(make):
    assert scanner.scan("", make()) == []


# ----------------------------------------------------------------------------- coverage limits


def test_unsupported_filter_is_reported_not_guessed():
    f = rules(fx.ascii85_stream_pdf())["CUSTOM_PDF_COVERAGE_LIMITED"]
    assert f.severity == Severity.INFO and "1 object stream(s) not inspected: filter ASCII85Decode" in f.description


def test_truncated_object_stream_is_reported_as_partly_inspected():
    f = rules(fx.truncated_flate_pdf())["CUSTOM_PDF_COVERAGE_LIMITED"]
    assert "only partly readable" in f.description and "object stream of object 5 0" in f.description


def test_encrypted_document_is_reported_as_not_fully_inspected():
    data = encrypted_pdf("")
    assert parse(data).encrypted
    f = rules(data)["CUSTOM_PDF_COVERAGE_LIMITED"]
    assert f.severity == Severity.INFO and "the document is encrypted" in f.description


def test_object_streams_of_an_encrypted_document_are_counted_as_not_inspected():
    data = fx.make_pdf(objects={5: fx.stream_object(f"{fx.OBJSTM} /Filter /FlateDecode", b"ciphertext"),
                                6: "<< /Filter /Standard /V 2 >>"}).replace(b"/Root 1 0 R", b"/Root 1 0 R /Encrypt 6 0 R")
    assert parse(data).not_inspected == {"the document is encrypted": 1}


# ----------------------------------------------------------------------------- malformed


@pytest.mark.parametrize("make, message", [
    (fx.no_objects_pdf, "no indirect object"),
    (fx.unterminated_string_pdf, "never closed"),
    (fx.unterminated_stream_pdf, "no endstream"),
])
def test_malformed_documents_fail_closed_as_invalid_structure(make, message):
    with pytest.raises(CustomScanError, match=message) as e:
        scanner.scan("", make())
    assert classify(e.value) == "invalid_structure"


@pytest.mark.parametrize("limit, value", [("MAX_STREAM_BYTES", 10), ("MAX_STREAMS", 0), ("MAX_ESCAPED_NAMES", 1)])
def test_analysis_limits_fail_closed(monkeypatch, limit, value):
    monkeypatch.setattr(pdf_syntax, limit, value)
    with pytest.raises(CustomScanError) as e:
        scanner.scan("", fx.obfuscated_javascript_pdf(in_object_stream=True))
    assert classify(e.value) == "invalid_structure"


def test_unexpected_defects_are_not_reported_as_malformed_input(monkeypatch):
    def broken(data):
        raise KeyError("programming error")

    monkeypatch.setattr(pdf_syntax, "parse", broken)
    with pytest.raises(KeyError) as e:
        scanner.scan("", fx.plain_pdf())
    assert classify(e.value) == "unexpected"


# ----------------------------------------------------------------------------- registry and API


def status(body: dict, name: str = "custom") -> dict:
    return next(s for s in body["scanners"] if s["name"] == name)


def test_custom_scanner_is_registered_and_ready():
    assert isinstance(main.SCANNERS[-1], CustomScanner)
    health = client.get("/health").json()
    assert health["scanners_registered"] == health["scanners_ready"] == 4


def test_api_reports_c1_alongside_the_other_scanners_with_independent_attribution():
    body = post_scan(client, fx.obfuscated_javascript_pdf()).json()
    assert body["verdict"] == Verdict.SUSPICIOUS  # MEDIUM findings, existing severity policy
    assert status(body)["status"] == "completed"
    assert body["message"].startswith("Analysed by 3 of 4 scanners (1 not applicable")
    by_scanner = {}
    for f in body["findings"]:
        by_scanner.setdefault(f["scanner"], set()).add(f["rule_id"])
    assert by_scanner["custom"] == {"CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"}
    assert "yara-x" not in by_scanner  # the escaped names defeat the byte signatures
    assert {"PDF_JAVASCRIPT", "PDF_AUTO_JAVASCRIPT"} <= by_scanner["pdf"]  # pypdf still sees JavaScript


def test_api_clean_pdf_is_safe_with_four_scanners():
    body = post_scan(client, fx.plain_pdf()).json()
    assert body["verdict"] == Verdict.SAFE and body["complete"]
    assert status(body)["status"] == "completed"


def test_api_non_pdf_is_not_applicable_for_the_custom_scanner():
    body = post_scan(client, make_ooxml({})).json()
    assert status(body)["status"] == "not_applicable"
    assert body["verdict"] == Verdict.SAFE


def test_api_malformed_pdf_fails_closed_with_the_custom_failure_reason(caplog):
    with caplog.at_level(logging.INFO, logger="app.main"):
        body = post_scan(client, fx.unterminated_string_pdf(), "broken.pdf").json()
    assert status(body)["status"] == "failed" and status(body)["error_kind"] == "invalid_structure"
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and not body["complete"]
    [record] = [r for r in caplog.records if "scanner=custom" in r.getMessage()]
    assert record.levelno == logging.WARNING and record.exc_info is None
    assert "custom detector's analysis limits" in record.getMessage()
    assert "broken.pdf" not in caplog.text and "never closed" not in caplog.text


def test_real_isolated_worker_runs_c1():
    # A real `python -m app.worker` child: process + audit hook everywhere; the Linux controls
    # (namespaces, capabilities, rlimits) only in Linux CI, see tests/test_worker_linux.py.
    report = asyncio.run(worker.run(fx.obfuscated_javascript_pdf(in_object_stream=True)))
    assert next(s for s in report.scanners if s.name == "custom").status == "completed"
    assert "CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME" in {f.rule_id for f in report.findings if f.scanner == "custom"}
    assert report.isolation["process"] and report.isolation["audit_hook"]
