"""Custom detector: the FilesMagic capstone's own explainable static indicators (fourth scanner).

It implements the Scanner contract (app.scanners.base) and runs in the same isolated worker as
the other scanners, on the same bytes. It neither calls nor reads the results of YARA-X, the
Office scanner or the PDF scanner, and uses no third-party parser: its PDF lexer is its own
(pdf_syntax). Findings carry scanner="custom", a rule ID, evidence and, where known, a location.

Implemented (Week 1): C1, PDF name-token obfuscation (pdf.py).
Not yet: Word, Excel and PowerPoint (C4-C10); an OOXML document is "not applicable" for now.
Legacy OLE formats (.doc/.xls/.ppt) are out of scope.
"""

from app.models import Finding
from app.scanners.custom import pdf, pdf_syntax
from app.scanners.custom.errors import CustomScanError

__all__ = ["CustomScanError", "CustomScanner"]


class CustomScanner:
    name = "custom"

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        if not pdf_syntax.is_pdf(data):  # format from content only, never the filename
            return None
        return [signal.to_finding() for signal in pdf.analyse(pdf_syntax.parse(data))]
