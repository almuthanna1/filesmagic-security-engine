"""worker.classify() maps scanner failures to a kind: invalid_structure / malformed_input
for expected rejections of hostile or broken files, unexpected for possible scanner bugs.

The key regression this guards (audit finding P1-a): a scanner other than PDF/Office must be
classified correctly. A future custom detector only has to subclass ScanError and declare its
malformed_causes; it must NOT fall through to "unexpected" for its own expected errors.
"""

from xml.etree.ElementTree import ParseError as XMLParseError
from zipfile import BadZipFile

from pypdf.errors import PdfReadError, PdfStreamError

from app.scanners.base import ScanError
from app.scanners.office import OfficeScanError
from app.scanners.pdf import PdfScanError
from app.worker import classify


def raised(exc: Exception, cause: BaseException | None = None) -> Exception:
    """Return `exc` as if raised, optionally `from cause`, so __cause__ is set like at runtime."""
    try:
        if cause is not None:
            try:
                raise cause
            except BaseException as c:
                raise exc from c
        raise exc
    except Exception as e:
        return e


# --- a stand-in for the future custom scanner: a ScanError subclass with its own causes ---


class CustomScanError(ScanError):
    malformed_causes = (ValueError,)


def test_custom_scanner_structure_check_is_invalid_structure():
    # Raised by the scanner's own limit/structure check, no underlying parser error.
    assert classify(raised(CustomScanError("too many objects"))) == "invalid_structure"


def test_custom_scanner_parser_rejection_is_malformed_input():
    assert classify(raised(CustomScanError("bad input"), ValueError("nope"))) == "malformed_input"


def test_custom_scanner_unrelated_cause_is_unexpected():
    # A cause the scanner did not declare as malformed: treat as a possible bug, not hostile input.
    assert classify(raised(CustomScanError("boom"), KeyError("x"))) == "unexpected"


def test_plain_exception_is_unexpected():
    assert classify(raised(RuntimeError("code problem"))) == "unexpected"
    assert classify(raised(RecursionError())) == "unexpected"


# --- existing PDF/Office behaviour must be unchanged ---


def test_pdf_structure_check_is_invalid_structure():
    assert classify(raised(PdfScanError("PDF structure exceeds 200000 objects"))) == "invalid_structure"


def test_pdf_read_error_is_malformed_input():
    assert classify(raised(PdfScanError("parse failed"), PdfReadError("truncated"))) == "malformed_input"
    # PdfStreamError subclasses PdfReadError, so it is covered too.
    assert classify(raised(PdfScanError("parse failed"), PdfStreamError("bad stream"))) == "malformed_input"


def test_pdf_scan_error_wrapping_an_unrelated_error_is_unexpected():
    assert classify(raised(PdfScanError("parse failed"), RuntimeError("bug"))) == "unexpected"


def test_office_structure_check_is_invalid_structure():
    assert classify(raised(OfficeScanError("part too large to analyse"))) == "invalid_structure"


def test_office_malformed_causes_are_malformed_input():
    for cause in (BadZipFile("not a zip"), XMLParseError("bad xml")):
        assert classify(raised(OfficeScanError("analysis failed"), cause)) == "malformed_input"


def test_office_scan_error_wrapping_an_unrelated_error_is_unexpected():
    assert classify(raised(OfficeScanError("analysis failed"), RuntimeError("bug"))) == "unexpected"
