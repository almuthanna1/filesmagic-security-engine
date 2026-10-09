from app.scanners.base import Scanner
from app.scanners.office import OfficeScanner
from app.scanners.pdf import PdfScanner
from app.scanners.yarax import YaraXScanner

# Scanners run by POST /scan. A scanner that fails (for example, rules that do not
# compile) makes the scan UNABLE_TO_SCAN, never SAFE.
SCANNERS: list[Scanner] = [YaraXScanner(), OfficeScanner(), PdfScanner()]
