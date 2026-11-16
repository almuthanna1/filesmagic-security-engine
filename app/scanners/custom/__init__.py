"""Custom detector: the FilesMagic capstone's own explainable static indicators (fourth scanner).

It implements the Scanner contract (app.scanners.base) and runs in the same isolated worker as
the other scanners, on the same bytes. It neither calls nor reads the results of YARA-X, the
Office scanner or the PDF scanner, and uses no third-party document parser: its PDF lexer
(pdf_syntax) and OOXML package reader (ooxml_package, on zipfile and defusedxml) are its own.
Findings carry scanner="custom", a rule ID, evidence and, where known, a location.

Implemented:
  C1      PDF name-token obfuscation (pdf.py)
  C4-C6   OOXML declaration, relationship-graph and ZIP container indicators (ooxml.py) for
          Word (docx docm dotx dotm), Excel (xlsx xlsm xltx xltm xlam; xlsb at container and
          declaration level) and PowerPoint (pptx pptm ppsx ppsm potx potm ppam)
Not yet: Word fields (C7), Excel formulas and names (C8-C9), PowerPoint actions (C10).
Out of scope: legacy OLE formats (.doc/.xls/.ppt) and encrypted OOXML (an OLE container), which
are "not applicable" here; the Office scanner covers them.
"""

from app.models import Finding
from app.scanners.custom import ooxml, ooxml_package, pdf, pdf_syntax
from app.scanners.custom.errors import CustomScanError

__all__ = ["CustomScanError", "CustomScanner"]


class CustomScanner:
    name = "custom"

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        # Format from content only, never the filename. A file that is both a PDF and an OPC
        # package (a polyglot) is analysed as both.
        signals, applicable = [], False
        if pdf_syntax.is_pdf(data):
            applicable = True
            signals += pdf.analyse(pdf_syntax.parse(data))
        if package := ooxml_package.open_package(data):
            applicable = True
            signals += ooxml.analyse(package)
        return [s.to_finding() for s in signals] if applicable else None
