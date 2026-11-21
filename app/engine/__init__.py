"""FilesMagic Unified Security Engine: the scanners every scan runs, followed by evidence correlation.

Run by `python -m app.worker --engine=unified`. Every detection decision is made by this
repository's own code; third-party libraries only parse (pypdf, olefile, oletools' VBA source
extraction, msoffcrypto, zipfile/defusedxml). See docs/custom-detection-rebuild/.
"""

from app.engine.correlate import LinkScanner, PdfChainScanner, VbaChainScanner, correlate
from app.engine.pdf_integrity import PdfIntegrityScanner
from app.engine.signatures import SignatureScanner, ruleset_hash
from app.engine.word_fields import FieldScanner
from app.scanners.custom import CustomScanner
from app.scanners.office import OfficeScanner
from app.scanners.pdf import PdfScanner

SCANNERS = [SignatureScanner(), OfficeScanner(), PdfScanner(), CustomScanner(), PdfChainScanner(),
            PdfIntegrityScanner(), VbaChainScanner(), LinkScanner(), FieldScanner()]

__all__ = ["SCANNERS", "correlate", "ruleset_hash"]
