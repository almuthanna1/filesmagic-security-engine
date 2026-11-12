"""FilesMagic custom document-security engine (capstone candidate).

The reference scanners (app.scanners.SCANNERS, unchanged) plus the engine's own components,
followed by evidence correlation. Run only by `python -m app.worker --engine=unified`; the API's
/scan keeps using the reference scanners, which stay the comparison baseline. See
docs/custom-engine-research-log.md.
"""

from pathlib import Path

from app.engine.correlate import SIGNATURES, LinkScanner, PdfChainScanner, VbaChainScanner, correlate
from app.engine.elf_scan import ElfScanner
from app.engine.word_fields import FieldScanner
from app.scanners import SCANNERS as REFERENCE_SCANNERS
from app.scanners.yarax import YaraXScanner

RULES_DIR = Path(__file__).resolve().parent / "rules"


class EngineSignatures(YaraXScanner):
    """The engine's own YARA-X rules (app/engine/rules), with the reference scanner's compiler
    checks, timeout, match cap and fail-closed handling."""

    name = SIGNATURES

    def __init__(self, rules_dir: Path = RULES_DIR):
        super().__init__(rules_dir)


SCANNERS = [*REFERENCE_SCANNERS, EngineSignatures(), PdfChainScanner(), VbaChainScanner(), LinkScanner(),
            FieldScanner(), ElfScanner()]

__all__ = ["SCANNERS", "correlate"]
