"""Bounded validation of PDF page-content streams for the unified research engine.

This is an integrity/coverage check, not a renderer or a PDF validator. It only resolves page
``/Contents`` and decodes a small allow-list of byte filters through pypdf while the existing
worker limits are active. It never executes content, fetches data, or starts an external decoder.
"""

import io
import logging

from pypdf import PasswordType, PdfReader, apply_configuration
from pypdf.generic import ArrayObject, IndirectObject, StreamObject

from app.models import CoverageIssue, Finding, Severity
from app.scanners.base import ScanError
from app.scanners.pdf import MAX_OBJECTS, PDF_LIMITS, _RepairLog, clean, is_pdf

NAME = "pdf-integrity"
MAX_CONTENT_STREAMS = 10_000
MAX_TOTAL_DECODED_BYTES = 32 * 1024 * 1024
SUPPORTED_FILTERS = {"/FlateDecode", "/Fl", "/LZWDecode", "/LZW", "/ASCIIHexDecode", "/AHx",
                     "/ASCII85Decode", "/A85", "/RunLengthDecode", "/RL"}


class PdfIntegrityError(ScanError):
    malformed_causes = ()


def _resolve(value):
    return value.get_object() if isinstance(value, IndirectObject) else value


def _filters(stream: StreamObject) -> list[str] | None:
    value = _resolve(stream.get("/Filter"))
    if value is None:
        return []
    if isinstance(value, ArrayObject):
        return [str(_resolve(item)) for item in value]
    return [str(value)]


class PdfIntegrityScanner:
    name = NAME

    def __init__(self):
        self.coverage_issues: list[CoverageIssue] = []

    def _issue(self, code: str, detail: str) -> None:
        if len(self.coverage_issues) < 50:
            self.coverage_issues.append(CoverageIssue(code=code, scanner=self.name, detail=detail))

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        self.coverage_issues = []
        if not is_pdf(data):
            return None
        log, logger = _RepairLog(), logging.getLogger("pypdf")
        logger.addHandler(log)
        try:
            with apply_configuration(**PDF_LIMITS):
                reader = PdfReader(io.BytesIO(data), strict=False)
                if reader.is_encrypted and reader.decrypt("") == PasswordType.NOT_DECRYPTED:
                    self._issue("PDF_ENCRYPTED_CONTENT_UNAVAILABLE", "Page content requires a password.")
                    return self._findings()
                total, streams = 0, 0
                for page in reader.pages:
                    contents = _resolve(page.get("/Contents"))
                    if contents is None:  # blank pages legitimately omit /Contents
                        continue
                    values = contents if isinstance(contents, ArrayObject) else [contents]
                    for value in values:
                        stream = _resolve(value)
                        streams += 1
                        if streams > MAX_CONTENT_STREAMS or streams > MAX_OBJECTS:
                            self._issue("PDF_CONTENT_STREAM_LIMIT", "Too many page-content streams.")
                            return self._findings()
                        if not isinstance(stream, StreamObject):
                            self._issue("PDF_CONTENT_STREAM_UNRESOLVED", "A page /Contents value is not a stream.")
                            continue
                        filters = _filters(stream)
                        if filters is None or any(name not in SUPPORTED_FILTERS for name in filters):
                            names = ", ".join(filters or ["indirect filter"])
                            self._issue("PDF_CONTENT_FILTER_UNSUPPORTED", f"Unsupported page-content filter: {names}.")
                            continue
                        try:
                            decoded = stream.get_data()
                        except Exception as e:
                            code = "PDF_CONTENT_LZW_DECODE_FAILED" if any(name in {"/LZWDecode", "/LZW"} for name in filters) else "PDF_CONTENT_DECODE_FAILED"
                            self._issue(code, f"Page-content decoding failed: {type(e).__name__}.")
                            continue
                        total += len(decoded)
                        if total > MAX_TOTAL_DECODED_BYTES:
                            self._issue("PDF_CONTENT_TOTAL_LIMIT", "Decoded page content exceeds the document limit.")
                            return self._findings()
        except Exception as e:
            raise PdfIntegrityError(f"PDF page-content analysis failed: {type(e).__name__}: {clean(e, 200)}") from e
        finally:
            logger.removeHandler(log)
        if log.count:
            self._issue("PDF_PARSER_REPAIRED", f"pypdf repaired {log.count} structural problem(s).")
        return self._findings()

    def _findings(self) -> list[Finding]:
        if not self.coverage_issues:
            return []
        codes = ", ".join(issue.code for issue in self.coverage_issues[:3])
        return [Finding(scanner=self.name, category="pdf-coverage", severity=Severity.INFO,
                        rule_id="ENGINE_PDF_COVERAGE_INCOMPLETE",
                        description=f"Required PDF coverage is incomplete. Evidence: {codes}.")]
