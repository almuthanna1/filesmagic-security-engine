"""FilesMagic custom document-security engine (capstone candidate).

The reference scanners (app.scanners.SCANNERS, unchanged) plus the engine's own components,
followed by evidence correlation. Run only by `python -m app.worker --engine=unified`; the API's
/scan keeps using the reference scanners, which stay the comparison baseline. See
docs/custom-engine-research-log.md.
"""

from app.engine.correlate import PdfChainScanner, correlate
from app.scanners import SCANNERS as REFERENCE_SCANNERS

SCANNERS = [*REFERENCE_SCANNERS, PdfChainScanner()]

__all__ = ["SCANNERS", "correlate"]
