"""Error contract of the custom detector (see app.scanners.base.ScanError)."""

from app.scanners.base import ScanError


class CustomScanError(ScanError):
    """The custom detector could not analyse the document reliably. The message is safe to return.

    Week 1 raises this only from its own structure and limit checks, with no __cause__, so the
    worker classifies every such failure as invalid_structure. Parser exceptions that mean
    malformed input (e.g. zipfile.BadZipFile for OOXML) are added to malformed_causes together
    with the code that wraps them; until then any wrapped exception is treated as unexpected.
    """

    malformed_causes = ()
