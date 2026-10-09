"""PDF scanner: structural analysis of PDF documents with pypdf.

A file is a PDF if "%PDF-" appears in its first 1024 bytes (where readers accept the
header); anything else returns None ("not applicable").

The object graph is walked iteratively from the document catalog: every indirect
object is visited at most once per trigger context (so reference cycles terminate),
nesting depth and the number of visited objects are capped, and bulky branches that
cannot hold actions (fonts, resources, page content, appearance streams) are skipped.
Nothing is executed or fetched: JavaScript is only searched as text, embedded files
are only inspected by name/type, URIs are only classified by scheme. pypdf runs with
tightened decompression limits and without the external jbig2dec decoder. Any parser
error raises PdfScanError, so the scan is UNABLE_TO_SCAN rather than SAFE.
"""

import io
import logging
import re
import threading
from collections import defaultdict

from pypdf import PasswordType, PdfReader, apply_configuration
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject

from app.models import Finding, Severity

NAME = "pdf"

MAX_DEPTH = 64  # nesting of direct dictionaries/arrays inside one object
MAX_OBJECTS = 200_000  # dictionaries/arrays visited per document
MAX_JS_BYTES = 1024 * 1024  # JavaScript text searched per script
MAX_DECODED_STREAM = 20 * 1024 * 1024  # per stream; pypdf defaults to 75 MB

PDF_LIMITS = dict(
    zlib_maximum_output_length=MAX_DECODED_STREAM,
    lzw_maximum_output_length=MAX_DECODED_STREAM,
    run_length_maximum_output_length=MAX_DECODED_STREAM,
    array_based_stream_maximum_output_length=MAX_DECODED_STREAM,
    maximum_declared_stream_length=MAX_DECODED_STREAM,
    jbig2dec_binary=None,  # never let a PDF make pypdf start an external program
)

# Keys whose subtrees cannot carry actions, embedded files or forms: skipping them keeps
# the walk proportional to the interactive structure, not to fonts and page content.
SKIP_KEYS = {
    "/Parent", "/P", "/Resources", "/Font", "/XObject", "/ColorSpace", "/ExtGState", "/Pattern",
    "/Shading", "/Contents", "/AP", "/Metadata", "/StructTreeRoot", "/Thumb", "/Widths",
    "/FontDescriptor", "/FontFile", "/FontFile2", "/FontFile3", "/ToUnicode", "/Encoding",
}
# /AA triggers that fire without the user clicking or typing: page open (/O), annotation
# page open/visible (/PO, /PV), document close/save/print (/WC /WS /DS /WP /DP).
AUTO_TRIGGERS = {"/O", "/PO", "/PV", "/WC", "/WS", "/DS", "/WP", "/DP"}

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "ps1", "msi", "dll", "cpl", "lnk", "jar", "reg", "inf", "scf", "url", "chm", "iso", "msc",
    "docm", "xlsm", "pptm", "dotm",
}
DANGEROUS_MIME = re.compile(r"msdownload|x-dosexec|x-executable|x-msi|x-sh\b|javascript|x-ms-shortcut|hta", re.I)
DANGEROUS_SCHEMES = {"javascript", "vbscript", "data", "mhtml", "search-ms", "shell", "its", "mk"}
# JavaScript APIs tied to historic Acrobat exploits, or that launch an attachment.
EXPLOIT_JS = re.compile(
    r"util\.printf|Collab\.getIcon|Collab\.collectEmailInfo|media\.newPlayer|spell\.customDictionaryOpen"
    r"|\.getAnnots\s*\(|exportDataObject\s*\([^)]*nLaunch\s*:\s*[12]",
    re.I,
)


class PdfScanError(RuntimeError):
    """The PDF could not be analysed reliably."""


def clean(text, limit: int = 100) -> str:
    text = re.sub(r"[\x00-\x1f\x7f]", "?", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def finding(category: str, severity: Severity, description: str, rule_id: str) -> Finding:
    return Finding(scanner=NAME, category=category, severity=severity, description=description, rule_id=rule_id)


def is_pdf(data: bytes) -> bool:
    return b"%PDF-" in data[:1024]


class _RepairLog(logging.Handler):
    """Counts pypdf warnings raised by the current thread (pypdf logs repairs it makes)."""

    def __init__(self):
        super().__init__(logging.WARNING)
        self.thread, self.count = threading.get_ident(), 0

    def emit(self, record):
        if threading.get_ident() == self.thread:
            self.count += 1


class PdfScanner:
    name = NAME

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        if not is_pdf(data):
            return None
        log, pypdf_logger = _RepairLog(), logging.getLogger("pypdf")
        pypdf_logger.addHandler(log)
        try:
            with apply_configuration(**PDF_LIMITS):
                found = analyse(data)
        except PdfScanError:
            raise
        except Exception as e:  # any parser failure, including RecursionError on hostile nesting
            raise PdfScanError(f"PDF analysis failed: {type(e).__name__}: {clean(e, 200)}") from e
        finally:
            pypdf_logger.removeHandler(log)
        if log.count:
            found.append(finding("pdf-structure", Severity.INFO,
                                 f"PDF has structural errors the parser had to repair ({log.count} warnings).",
                                 "PDF_STRUCTURE_REPAIRED"))
        return found


def text_of(value, limit: int = MAX_JS_BYTES) -> str:
    """String or stream content as text, bounded."""
    value = value.get_object() if isinstance(value, IndirectObject) else value
    if isinstance(value, StreamObject):
        raw = value.get_data()[:limit]
    elif isinstance(value, bytes):
        raw = value[:limit]
    else:
        return str(value)[:limit]
    return raw.decode("latin-1")


def filespec_name(value) -> str:
    value = value.get_object() if isinstance(value, IndirectObject) else value
    if isinstance(value, DictionaryObject):
        for key in ("/UF", "/F", "/Unix", "/DOS", "/Mac"):
            if key in value:
                return text_of(value[key], 1000)
        if "/Win" in value:
            return filespec_name(value["/Win"])
        return ""
    return text_of(value, 1000)


def analyse(data: bytes) -> list[Finding]:
    reader = PdfReader(io.BytesIO(data), strict=False)
    found: list[Finding] = []

    if reader.is_encrypted:
        # Many PDFs are encrypted only to restrict printing/editing, with an empty user
        # password; those open without a password and can be inspected normally.
        if reader.decrypt("") == PasswordType.NOT_DECRYPTED:
            return [finding("pdf-encrypted", Severity.MEDIUM,
                            "PDF is password-protected, so its contents cannot be inspected.", "PDF_ENCRYPTED")]
        found.append(finding("pdf-encrypted", Severity.INFO,
                             "PDF is encrypted with an empty user password (permission restrictions only); "
                             "contents were inspected.", "PDF_ENCRYPTED_PERMISSIONS_ONLY"))

    root = reader.trailer.get("/Root")
    if root is None:
        raise PdfScanError("PDF has no document catalog")

    js, auto_js, exploit_js = 0, 0, set()
    launches, attachments, dangerous_attachments = [], [], []
    uris = defaultdict(list)  # (rule_id) -> targets
    acroform = xfa = False

    seen: set[tuple] = set()
    visited = 0
    stack = [(root, 0, False)]  # (object, depth, reached through an automatic trigger)
    while stack:
        obj, depth, auto = stack.pop()
        if isinstance(obj, IndirectObject):
            key = (obj.idnum, obj.generation, auto)
            if key in seen:
                continue
            seen.add(key)
            obj = obj.get_object()
            # Depth bounds nesting inside one object; chains of references (outline
            # /Next lists, page trees) are bounded by `seen` and MAX_OBJECTS instead.
            depth = 0
        if not isinstance(obj, (DictionaryObject, ArrayObject)):
            continue
        visited += 1
        if visited > MAX_OBJECTS:
            raise PdfScanError(f"PDF structure exceeds {MAX_OBJECTS} objects")
        if depth > MAX_DEPTH:
            raise PdfScanError(f"PDF structure is nested deeper than {MAX_DEPTH} levels")

        if isinstance(obj, ArrayObject):
            stack.extend((item, depth + 1, auto) for item in obj)
            continue

        action = obj.get("/S")
        if "/JS" in obj:
            js += 1
            auto_js += auto
            matches = EXPLOIT_JS.findall(text_of(obj["/JS"]))
            exploit_js.update(clean(m, 40) for m in matches)
        if action == "/Launch":
            launches.append(filespec_name(obj.get("/F") or obj.get("/Win") or ""))
        if action == "/URI":
            target = text_of(obj.get("/URI", ""), 2000).strip()
            scheme = target.split(":", 1)[0].lower() if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) else ""
            if scheme in DANGEROUS_SCHEMES or scheme.startswith("ms-"):
                uris["PDF_URI_DANGEROUS_SCHEME"].append(target)
            elif scheme in ("file", "smb") or target.startswith(("\\\\", "//")):
                uris["PDF_URI_NETWORK_PATH"].append(target)
            elif scheme not in ("http", "https", "mailto", ""):
                uris["PDF_URI_OTHER_SCHEME"].append(target)
        if "/EF" in obj:
            name = clean(filespec_name(obj), 60)
            ef = obj["/EF"].get_object() if isinstance(obj["/EF"], IndirectObject) else obj["/EF"]
            stream = ef.get("/F") or ef.get("/UF") if isinstance(ef, DictionaryObject) else None
            stream = stream.get_object() if isinstance(stream, IndirectObject) else stream
            mime = str(stream.get("/Subtype", "")) if isinstance(stream, DictionaryObject) else ""
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            (dangerous_attachments if ext in DANGEROUS_EXTENSIONS or DANGEROUS_MIME.search(mime)
             else attachments).append(name or "(unnamed)")
        if "/AcroForm" in obj:
            acroform = True
            form = obj["/AcroForm"].get_object()
            xfa = xfa or (isinstance(form, DictionaryObject) and "/XFA" in form)

        for k, v in obj.items():
            if k in SKIP_KEYS:
                continue
            if k == "/OpenAction":
                stack.append((v, depth + 1, True))
            elif k == "/AA":
                triggers = v.get_object() if isinstance(v, IndirectObject) else v
                if isinstance(triggers, DictionaryObject):
                    for trig, act in triggers.items():
                        stack.append((act, depth + 1, auto or trig in AUTO_TRIGGERS))
            elif k == "/JavaScript" and not isinstance(v, str):
                stack.append((v, depth + 1, True))  # document-level scripts run when the file opens
            else:
                stack.append((v, depth + 1, auto))

    if js:
        found.append(finding("pdf-javascript", Severity.MEDIUM,
                             f"PDF contains {js} JavaScript action(s).", "PDF_JAVASCRIPT"))
    if auto_js:
        found.append(finding("pdf-javascript", Severity.MEDIUM,
                             f"{auto_js} JavaScript action(s) run automatically when the document or a page is "
                             "opened.", "PDF_AUTO_JAVASCRIPT"))
    if exploit_js:
        found.append(finding("pdf-javascript", Severity.HIGH,
                             f"JavaScript uses APIs associated with known PDF reader exploits or launching "
                             f"attachments: {', '.join(sorted(exploit_js)[:4])}.", "PDF_JAVASCRIPT_EXPLOIT_API"))
    for target in launches[:1]:
        found.append(finding("pdf-launch", Severity.HIGH,
                             f"PDF contains {len(launches)} /Launch action(s) that can start programs or open files"
                             f"{f' (e.g. {clean(target, 80)!r})' if target else ''}.", "PDF_LAUNCH_ACTION"))
    if attachments:
        found.append(finding("pdf-embedded-file", Severity.LOW,
                             f"PDF carries {len(attachments)} embedded file(s) (e.g. {attachments[0]!r}).",
                             "PDF_EMBEDDED_FILE"))
    if dangerous_attachments:
        found.append(finding("pdf-embedded-file", Severity.HIGH,
                             f"PDF carries an embedded executable, script or macro file: {dangerous_attachments[0]!r}.",
                             "PDF_EMBEDDED_EXECUTABLE"))
    if auto_js and (launches or attachments or dangerous_attachments):
        found.append(finding("pdf-javascript", Severity.HIGH,
                             "JavaScript runs automatically in a PDF that also carries an embedded file or launch "
                             "action, a common way to drop and open a payload.", "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD"))
    uri_text = {
        "PDF_URI_DANGEROUS_SCHEME": (Severity.HIGH, "use a URI scheme that can hand the link to another program"),
        "PDF_URI_NETWORK_PATH": (Severity.MEDIUM, "point to a network/file path; opening them can leak credentials"),
        "PDF_URI_OTHER_SCHEME": (Severity.INFO, "use an uncommon URI scheme"),
    }
    for rule_id, targets in uris.items():
        severity, why = uri_text[rule_id]
        found.append(finding("pdf-uri", severity, f"{len(targets)} link(s) {why} (e.g. {clean(targets[0], 80)!r}).",
                             rule_id))
    if acroform:
        found.append(finding("pdf-form", Severity.INFO, "PDF contains an interactive form (AcroForm).", "PDF_ACROFORM"))
    if xfa:
        found.append(finding("pdf-form", Severity.LOW,
                             "PDF contains an XFA form, which can carry scripts this scanner does not parse.",
                             "PDF_XFA_FORM"))
    return found
