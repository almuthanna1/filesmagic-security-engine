"""Regression tests for unified-only bounded PDF page-content coverage."""

import hashlib
import os
from urllib.request import urlopen

import pytest

from app import worker
from app.engine.pdf_integrity import PdfIntegrityScanner
from tests.custom_fixtures import stream_object
from tests.pdf_fixtures import encrypted_pdf, make_pdf


def lzw(*codes: int) -> bytes:
    """A short PDF LZW stream: 9-bit clear/text/EOD codes, sufficient for inert controls."""
    bits = "".join(f"{code:09b}" for code in codes)
    return int(bits + "0" * (-len(bits) % 8), 2).to_bytes((len(bits) + 7) // 8, "big")


def report(data: bytes):
    return worker.analyse([PdfIntegrityScanner()], data)


def codes(data: bytes) -> set[str]:
    return {issue.code for issue in report(data).coverage_issues}


def content_pdf(data: bytes, filters: str = "/LZWDecode") -> bytes:
    return make_pdf(objects={4: stream_object(f"/Filter {filters}", data)})


def test_valid_lzw_page_content_is_covered():
    data = content_pdf(lzw(256, *b"BT ET", 257))
    result = report(data)
    assert result.coverage_complete and result.coverage_issues == []


def test_direct_and_indirect_content_arrays_are_covered():
    data = make_pdf(objects={
        3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents [4 0 R 5 0 R] >>",
        4: stream_object("", b"BT ET"),
        5: stream_object("/Filter /LZWDecode", lzw(256, *b"BT ET", 257)),
    })
    assert report(data).coverage_complete


def test_invalid_lzw_page_content_is_incomplete_not_malicious():
    # The qpdf bad-data fixture's 48-byte stream, kept inline so this regression needs no network.
    invalid = bytes.fromhex("789c730ae15250d0773354303251084903b2cd8d80c840212405c8d608c82f492cc9d75408c9e2720de10200cb0109c8")
    result = report(content_pdf(invalid))
    assert not result.coverage_complete
    assert {i.code for i in result.coverage_issues} == {"PDF_CONTENT_LZW_DECODE_FAILED"}


def test_unsupported_page_filter_is_incomplete():
    assert codes(content_pdf(b"inert", "/DCTDecode")) == {"PDF_CONTENT_FILTER_UNSUPPORTED"}


def test_password_protected_content_is_incomplete():
    assert codes(encrypted_pdf("secret")) == {"PDF_ENCRYPTED_CONTENT_UNAVAILABLE"}


def test_empty_password_encryption_is_covered_when_page_content_is_readable():
    result = report(encrypted_pdf(""))
    assert result.coverage_complete and result.coverage_issues == []


def test_total_decoded_limit_is_reported(monkeypatch):
    from app.engine import pdf_integrity

    monkeypatch.setattr(pdf_integrity, "MAX_TOTAL_DECODED_BYTES", 2)
    assert codes(content_pdf(lzw(256, *b"BT ET", 257))) == {"PDF_CONTENT_TOTAL_LIMIT"}


def test_parser_repair_is_reported_as_incomplete_coverage():
    assert "PDF_PARSER_REPAIRED" in codes(make_pdf(header_offset=500))


@pytest.mark.skipif(os.environ.get("FILES_MAGIC_EXTERNAL_PDF") != "1", reason="pinned qpdf fixtures are opt-in")
@pytest.mark.parametrize(("name", "sha256", "expected"), [
    ("V4-aes.pdf", "1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240", set()),
    ("bad-data.pdf", "919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057", {"PDF_CONTENT_LZW_DECODE_FAILED"}),
])
def test_pinned_qpdf_regressions(name, sha256, expected):
    url = "https://raw.githubusercontent.com/qpdf/qpdf/4eba95899886e851cc41d76886483b347612f2a8/qpdf/qtest/qpdf/" + name
    data = urlopen(url, timeout=15).read()
    assert hashlib.sha256(data).hexdigest() == sha256
    assert {issue.code for issue in report(data).coverage_issues} == expected
