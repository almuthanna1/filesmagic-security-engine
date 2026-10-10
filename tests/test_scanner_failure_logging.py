"""Logging policy: malformed inputs get concise warnings; crashes keep tracebacks.

Every test goes through the actual /scan endpoint, exercising the fail-closed
decision policy as well as log severity and exception information.
"""

import logging

from fastapi.testclient import TestClient

from app import main
from app.models import Verdict
from app.scanners import pdf
from app.scanners.office import OfficeScanner
from app.scanners.pdf import PdfScanner
from tests.office_fixtures import make_ooxml


def scanner_logs(caplog):
    return [r for r in caplog.records if r.name == "app.main" and "scanner" in r.getMessage().lower()]


def test_corrupt_pdf_explained_as_warning_no_traceback(monkeypatch, caplog):
    monkeypatch.setattr(main, "SCANNERS", [PdfScanner()])
    with caplog.at_level(logging.WARNING, logger="app.main"):
        response = TestClient(main.app).post(
            "/scan", files={"file": ("corrupted.pdf", b"%PDF-1.4\nnot really a PDF\n")}
        )
    assert response.status_code == 200
    assert response.json()["verdict"] == Verdict.UNABLE_TO_SCAN
    records = scanner_logs(caplog)
    assert len(records) == 1
    record = records[0]
    assert record.levelno == logging.WARNING
    assert record.exc_info is None
    assert "corrupted.pdf" in record.getMessage()
    assert "malformed or truncated" in record.getMessage()
    assert "PdfStreamError" in record.getMessage()


def test_malformed_office_xml_explained_as_warning_no_traceback(monkeypatch, caplog):
    monkeypatch.setattr(main, "SCANNERS", [OfficeScanner()])
    bad_docx = make_ooxml({"word/_rels/document.xml.rels": "<broken"})
    with caplog.at_level(logging.WARNING, logger="app.main"):
        response = TestClient(main.app).post(
            "/scan", files={"file": ("corrupted.docx", bad_docx)}
        )
    assert response.status_code == 200
    assert response.json()["verdict"] == Verdict.UNABLE_TO_SCAN
    records = scanner_logs(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    assert records[0].exc_info is None
    assert "Office ZIP/XML structure" in records[0].getMessage()


def test_unexpected_scanner_crash_preserves_traceback(monkeypatch, caplog):
    class BrokenScanner:
        name = "broken"

        def scan(self, filename, data):
            raise RuntimeError("unexpected code problem")

    monkeypatch.setattr(main, "SCANNERS", [BrokenScanner()])
    with caplog.at_level(logging.WARNING, logger="app.main"):
        response = TestClient(main.app).post("/scan", files={"file": ("test.txt", b"safe")})
    assert response.status_code == 200
    assert response.json()["verdict"] == Verdict.UNABLE_TO_SCAN
    records = scanner_logs(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None
    assert "unexpected code problem" in records[0].getMessage() or "Unexpected scanner failure" in records[0].getMessage()


def test_unexpected_pdf_scanner_failure_wrapped_as_pdf_scan_error_still_traceback(monkeypatch, caplog):
    def broken_reader(*args, **kwargs):
        raise RuntimeError("unexpected programming failure")

    monkeypatch.setattr(pdf, "PdfReader", broken_reader)
    monkeypatch.setattr(main, "SCANNERS", [PdfScanner()])
    with caplog.at_level(logging.WARNING, logger="app.main"):
        response = TestClient(main.app).post(
            "/scan", files={"file": ("unexpected.pdf", b"%PDF-1.4\n")}
        )
    assert response.status_code == 200
    assert response.json()["verdict"] == Verdict.UNABLE_TO_SCAN
    records = scanner_logs(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.ERROR
    assert records[0].exc_info is not None
