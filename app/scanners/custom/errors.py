"""Error contract of the custom detector (see app.scanners.base.ScanError)."""

import zipfile
import zlib
from xml.etree.ElementTree import ParseError as XMLParseError

from defusedxml.common import DefusedXmlException

from app.scanners.base import ScanError


class CustomScanError(ScanError):
    """The custom detector could not analyse the document reliably. The message is safe to return.

    Raised with no __cause__ by its own structure and limit checks (invalid_structure). Raised
    from one of malformed_causes when the OOXML reader finds a broken ZIP container or XML part
    (malformed_input). Any other wrapped exception is a possible defect (unexpected). The PDF
    lexer never wraps an exception: corrupt PDF streams are reported as coverage instead.
    """

    malformed_causes = (zipfile.BadZipFile, zlib.error, EOFError, XMLParseError, DefusedXmlException)
