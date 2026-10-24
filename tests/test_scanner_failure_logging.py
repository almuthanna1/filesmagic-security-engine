"""Logging policy: malformed inputs get concise warnings; possible bugs get an ERROR with a
code-location trace.

Scanners run in the isolated worker, so the API logs what the worker reports: scanner
name, failure kind, exception type and (for unexpected failures) file:line:function
frames. It never logs the filename, file contents or exception messages, all of which
can be attacker-controlled. Every test goes through the actual /scan endpoint, exercising
the fail-closed decision policy as well as log severity and content.
"""

import logging

from fastapi.testclient import TestClient

from app import main
from app.models import Verdict
from app.scanners import pdf
from app.scanners.office import OfficeScanner
from app.scanners.pdf import PdfScanner
from tests.office_fixtures import make_ooxml
from tests.scan_client import post_scan

client = TestClient(main.app)


def scanner_logs(caplog):
    return [r for r in caplog.records if r.name == "app.main" and "scanner failure" in r.getMessage()]


def scan(caplog, data, filename):
    with caplog.at_level(logging.INFO, logger="app.main"):
        response = post_scan(client, data, filename)
    assert response.status_code == 200
    return response.json()


def test_corrupt_pdf_explained_as_warning_without_filename(monkeypatch, caplog):
    monkeypatch.setattr(main, "SCANNERS", [PdfScanner()])
    body = scan(caplog, b"%PDF-1.4\nnot really a PDF\n", "corrupted.pdf")
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert body["scanners"][0]["error_kind"] == "malformed_input"
    [record] = scanner_logs(caplog)
    message = record.getMessage()
    assert record.levelno == logging.WARNING and record.exc_info is None
    assert "scanner=pdf" in message and "kind=malformed_input" in message
    assert "malformed or truncated" in message
    assert "PdfStreamError" in message
    assert f"request_id={body['request_id']}" in message
    assert "corrupted.pdf" not in caplog.text


def test_malformed_office_xml_explained_as_warning(monkeypatch, caplog):
    monkeypatch.setattr(main, "SCANNERS", [OfficeScanner()])
    body = scan(caplog, make_ooxml({"word/_rels/document.xml.rels": "<broken"}), "corrupted.docx")
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    [record] = scanner_logs(caplog)
    assert record.levelno == logging.WARNING and record.exc_info is None
    assert "Office ZIP/XML structure" in record.getMessage()
    assert "corrupted.docx" not in caplog.text


def test_scanner_limit_is_invalid_structure(monkeypatch, caplog):
    monkeypatch.setattr(main, "SCANNERS", [PdfScanner()])
    monkeypatch.setattr(pdf, "MAX_OBJECTS", 1)
    from tests.pdf_fixtures import make_pdf

    body = scan(caplog, make_pdf(), "big.pdf")
    assert body["scanners"][0]["error_kind"] == "invalid_structure"
    [record] = scanner_logs(caplog)
    assert record.levelno == logging.WARNING
    assert "exceeds analysis limits" in record.getMessage()


def test_unexpected_scanner_crash_logs_error_with_code_trace(monkeypatch, caplog):
    class BrokenScanner:
        name = "broken"

        def scan(self, filename, data):
            raise RuntimeError("unexpected code problem with SECRET-DOC-TEXT")

    monkeypatch.setattr(main, "SCANNERS", [BrokenScanner()])
    body = scan(caplog, b"safe", "test.txt")
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    assert body["scanners"][0]["error_kind"] == "unexpected"
    [record] = scanner_logs(caplog)
    message = record.getMessage()
    assert record.levelno == logging.ERROR
    assert "type=RuntimeError" in message
    assert "test_scanner_failure_logging.py:" in message and ":scan" in message  # where it failed
    assert "SECRET-DOC-TEXT" not in caplog.text  # exception messages are not logged


def test_unexpected_failure_wrapped_as_pdf_scan_error_is_still_an_error(monkeypatch, caplog):
    def broken_reader(*args, **kwargs):
        raise RuntimeError("unexpected programming failure")

    monkeypatch.setattr(pdf, "PdfReader", broken_reader)
    monkeypatch.setattr(main, "SCANNERS", [PdfScanner()])
    body = scan(caplog, b"%PDF-1.4\n", "unexpected.pdf")
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN
    [record] = scanner_logs(caplog)
    assert record.levelno == logging.ERROR
    assert "kind=unexpected" in record.getMessage() and "broken_reader" in record.getMessage()


def test_worker_failure_logged_once_with_request_id(monkeypatch, caplog):
    async def dead_worker(data):
        raise main.worker.WorkerError("scan worker timed out after 30s")

    monkeypatch.setattr(main, "run_scan", dead_worker)
    body = scan(caplog, b"x", "x.bin")
    assert all(s["error_kind"] == "worker" for s in body["scanners"])
    worker_logs = [r for r in caplog.records if "scan worker failure" in r.getMessage()]
    assert len(worker_logs) == 1 and worker_logs[0].levelno == logging.ERROR
    assert f"request_id={body['request_id']}" in worker_logs[0].getMessage()
    assert scanner_logs(caplog) == []  # not repeated per scanner
