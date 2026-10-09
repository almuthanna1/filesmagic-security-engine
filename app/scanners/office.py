"""Office scanner: structural analysis of legacy OLE and OOXML Office documents.

Format is identified from content, never the filename:
  - OLE2 compound file with Office streams (.doc/.xls/.ppt, encrypted OOXML)
  - ZIP package with [Content_Types].xml (OOXML: .docx/.xlsx/.pptx and macro variants)
Anything else returns None ("not applicable"), so a PDF or image is not penalised.

Everything happens in memory: no temporary files, nothing is extracted to disk, and
macros/objects are never executed. XML is parsed with defusedxml (DTDs and entities
rejected). ZIP archives are checked for entry count, declared sizes and unsafe member
names before any member is read. Any parsing error raises OfficeScanError, so the scan
is UNABLE_TO_SCAN rather than SAFE.
"""

import io
import re
import zipfile
from collections import Counter

import defusedxml.ElementTree as SafeET
import msoffcrypto
import olefile
from oletools.oleobj import OleNativeStream
from oletools.olevba import VBA_Parser

from app.models import Finding, Severity

NAME = "office"

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"

# ZIP resource limits. Uploads are at most 10 MB, so real documents stay far below these.
MAX_ZIP_ENTRIES = 5000
MAX_TOTAL_UNCOMPRESSED = 256 * 1024 * 1024  # declared, across all entries
MAX_MEMBER_BYTES = 32 * 1024 * 1024  # largest single member we will read

OFFICE_OLE_STREAMS = {"worddocument", "workbook", "book", "powerpoint document", "encryptioninfo", "encryptedpackage"}
VBA_OLE_STORAGES = {"vba", "_vba_project_cur", "macros"}
EQUATION_EDITOR_CLSID = "0002CE02-0000-0000-C000-000000000046"

DANGEROUS_EXTENSIONS = {
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "ps1", "msi", "dll", "cpl", "lnk", "jar", "reg", "inf", "scf", "url", "chm", "iso", "msc",
}
# URI schemes that make Office hand the target to another handler (e.g. Follina used ms-msdt).
DANGEROUS_SCHEMES = {"mhtml", "javascript", "vbscript", "search-ms", "its", "mk", "shell"}
# Relationship types whose external targets Office loads automatically.
AUTO_LOAD_RELATIONSHIPS = {"oleObject", "attachedTemplate", "frame", "subDocument"}
DDE_SERVICES_RUNNING_COMMANDS = {
    "cmd", "powershell", "pwsh", "mshta", "rundll32", "regsvr32", "wscript", "cscript", "msiexec", "certutil",
}
# olevba "Suspicious" descriptions that mean code execution or download, not just file I/O.
STRONG_VBA_BEHAVIOUR = re.compile(
    r"run an executable|powershell|download files|inject code|shellcode|through WMI|VBA Stomping", re.IGNORECASE
)
WORD_FIELD_PARTS = re.compile(r"^word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml$", re.IGNORECASE)


class OfficeScanError(RuntimeError):
    """The document could not be analysed reliably."""


def clean(text: str, limit: int = 100) -> str:
    """Make attacker-controlled text safe and short enough to show in a finding."""
    text = re.sub(r"[\x00-\x1f\x7f]", "?", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def finding(category: str, severity: Severity, description: str, rule_id: str) -> Finding:
    return Finding(scanner=NAME, category=category, severity=severity, description=description, rule_id=rule_id)


def identify(data: bytes) -> str | None:
    if data.startswith(OLE_MAGIC):
        return "ole"
    if data.startswith(ZIP_MAGIC):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = {n.lower() for n in zf.namelist()}
        except zipfile.BadZipFile as e:
            # Unreadable ZIP that claims to be an Office package: fail closed.
            if b"[Content_Types].xml" in data:
                raise OfficeScanError(f"malformed OOXML package: {e}") from e
            return None
        return "ooxml" if "[content_types].xml" in names else None
    return None


class OfficeScanner:
    name = NAME

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        kind = identify(data)
        if kind is None:
            return None
        try:
            return scan_ole(data) if kind == "ole" else scan_ooxml(data)
        except OfficeScanError:
            raise
        except Exception as e:  # any parser failure on hostile input
            raise OfficeScanError(f"{kind.upper()} analysis failed: {type(e).__name__}: {clean(e, 200)}") from e


# ----------------------------------------------------------------------------- VBA


def vba_findings(ole_data: bytes, label: str, has_vba_storage: bool) -> list[Finding]:
    """olevba on an OLE blob (whole legacy file, or vbaProject.bin from OOXML).

    has_vba_storage: the container structurally holds a VBA project. If olevba then
    finds no macros, the project is damaged or tampered with; report it, don't pass it.
    """
    unparsed = [finding("office-macro", Severity.LOW,
                        "Document contains a VBA project storage that could not be parsed.", "OFFICE_VBA_UNPARSED")]
    if has_vba_storage and not ole_data.startswith(OLE_MAGIC):
        return unparsed  # a VBA project is always OLE; olevba would misread other data as VBA text
    parser = VBA_Parser(label, data=ole_data)
    try:
        if not parser.detect_macros():
            return unparsed if has_vba_storage else []
        results = parser.analyze_macros()
    finally:
        parser.close()

    autoexec = sorted({clean(kw, 40) for kind, kw, _ in results if kind == "AutoExec"})
    suspicious = {clean(desc, 90) for kind, _, desc in results if kind == "Suspicious"}
    strong = sorted(d for d in suspicious if STRONG_VBA_BEHAVIOUR.search(d))
    weak = sorted(suspicious - set(strong))
    obfuscation = sorted({kind for kind, _, _ in results if kind in ("Hex String", "Base64 String", "Dridex String", "VBA obfuscated Strings")})

    found = [finding("office-macro", Severity.LOW, "Document contains a VBA/XLM macro project.", "OFFICE_MACROS_PRESENT")]
    if autoexec:
        found.append(finding("office-macro-autoexec", Severity.MEDIUM,
                             f"Macro code runs automatically via: {', '.join(autoexec[:5])}.", "OFFICE_MACRO_AUTOEXEC"))
    if strong:
        found.append(finding("office-macro-suspicious", Severity.MEDIUM,
                             f"Macro code {'; '.join(strong[:4])}.", "OFFICE_MACRO_DANGEROUS_CAPABILITY"))
    if weak:
        found.append(finding("office-macro-suspicious", Severity.LOW,
                             f"Macro code {'; '.join(weak[:4])}.", "OFFICE_MACRO_SUSPICIOUS_KEYWORDS"))
    if obfuscation:
        found.append(finding("office-macro-obfuscation", Severity.LOW,
                             f"Macro code contains encoded or obfuscated strings ({', '.join(obfuscation)}).",
                             "OFFICE_MACRO_OBFUSCATION"))
    if autoexec and strong:
        found.append(finding("office-macro-autoexec", Severity.HIGH,
                             "Macro code runs automatically on open and can execute commands or download files.",
                             "OFFICE_MACRO_AUTOEXEC_EXECUTION"))
    return found


# ----------------------------------------------------------------------------- OLE objects


def ole_object_findings(ole: olefile.OleFileIO, where: str) -> list[Finding]:
    """Embedded-object checks on an OLE container (legacy document or OOXML embedding)."""
    found = []
    entries = ole.listdir(streams=True, storages=True)
    if any((ole.getclsid(e) or "").upper() == EQUATION_EDITOR_CLSID for e in entries) or (
        (ole.root.clsid or "").upper() == EQUATION_EDITOR_CLSID
    ):
        found.append(finding("office-embedded-object", Severity.HIGH,
                             f"{where} contains a Microsoft Equation Editor 3.0 object, a component removed from "
                             "Office after it was widely exploited (CVE-2017-11882).", "OFFICE_EQUATION_EDITOR"))
    for entry in entries:
        if entry[-1] == "\x01Ole10Native":
            native = OleNativeStream(ole.openstream(entry).read(), package=False)
            embedded_name = clean(native.filename or native.src_path or "", 60)
            ext = embedded_name.rsplit(".", 1)[-1].lower() if "." in embedded_name else ""
            if ext in DANGEROUS_EXTENSIONS:
                found.append(finding("office-embedded-object", Severity.HIGH,
                                     f"{where} embeds a file with an executable/script type: '{embedded_name}'.",
                                     "OFFICE_PACKAGE_EXECUTABLE"))
            else:
                found.append(finding("office-embedded-object", Severity.MEDIUM,
                                     f"{where} embeds a file as an OLE Package object"
                                     f"{f': {embedded_name!r}' if embedded_name else ''}.", "OFFICE_PACKAGE_OBJECT"))
    return found


def scan_ole(data: bytes) -> list[Finding] | None:
    with olefile.OleFileIO(data) as ole:
        entries = ole.listdir(streams=True, storages=True)
        top = {e[0].lower() for e in entries}
        has_vba = any(part.lower() in VBA_OLE_STORAGES for e in entries for part in e)
        if not (top & OFFICE_OLE_STREAMS or has_vba):
            return None  # an OLE file, but not an Office document (e.g. MSI, Outlook .msg)

        found = []
        if {"encryptioninfo", "encryptedpackage"} <= top:
            # Encrypted OOXML: the whole package is ciphertext, nothing more to inspect.
            return [finding("office-encrypted", Severity.MEDIUM,
                            "Document is password-protected/encrypted, so its contents cannot be inspected.",
                            "OFFICE_ENCRYPTED")]
        if top & {"worddocument", "workbook", "powerpoint document"}:
            if msoffcrypto.OfficeFile(io.BytesIO(data)).is_encrypted():
                found.append(finding("office-encrypted", Severity.MEDIUM,
                                     "Document is password-protected/encrypted, so its contents cannot be fully "
                                     "inspected.", "OFFICE_ENCRYPTED"))

        found += ole_object_findings(ole, "Document")
        object_storages = [e for e in entries if len(e) == 2 and (e[0].lower() == "objectpool" or e[0].startswith("MBD"))]
        if object_storages and not any(f.category == "office-embedded-object" for f in found):
            found.append(finding("office-embedded-object", Severity.LOW,
                                 f"Document contains {len({tuple(e) for e in object_storages})} embedded OLE object(s).",
                                 "OFFICE_EMBEDDED_OLE"))

    if has_vba or top & {"workbook", "book"}:  # workbook: olevba also detects XLM macros
        found += vba_findings(data, "document", has_vba_storage=has_vba)
    return found


# ----------------------------------------------------------------------------- OOXML


def unsafe_member_name(name: str) -> bool:
    return (
        name.startswith(("/", "\\"))
        or "\\" in name
        or "\x00" in name
        or re.match(r"^[a-zA-Z]:", name) is not None
        or ".." in name.split("/")
    )


def read_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size > MAX_MEMBER_BYTES:
        raise OfficeScanError(f"package part {clean(info.filename, 60)!r} is too large to analyse")
    with zf.open(info) as f:
        return f.read(MAX_MEMBER_BYTES + 1)  # zipfile also stops at the declared size


def iter_xml(zf: zipfile.ZipFile, info: zipfile.ZipInfo):
    """Yield parsed elements one by one, keeping memory flat for large parts."""
    if info.file_size > MAX_MEMBER_BYTES:
        raise OfficeScanError(f"package part {clean(info.filename, 60)!r} is too large to analyse")
    with zf.open(info) as f:
        for _, element in SafeET.iterparse(f, events=("end",), forbid_dtd=True):
            yield element
            element.clear()


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def external_relationship(rel_type: str, target: str) -> tuple[str, Severity, str, str] | None:
    """Classify one TargetMode="External" relationship: (category, severity, rule_id, why)."""
    t = target.strip()
    scheme = t.split(":", 1)[0].lower() if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", t) else ""
    if scheme in DANGEROUS_SCHEMES or scheme.startswith("ms-") or t.endswith("!"):
        return ("office-external-relationship", Severity.HIGH, "OFFICE_EXTERNAL_DANGEROUS_SCHEME",
                "uses a URI scheme that can hand the target to another program")
    unc = t.startswith(("\\\\", "//")) or scheme == "file"
    if rel_type in AUTO_LOAD_RELATIONSHIPS:
        return ("office-external-relationship", Severity.MEDIUM, "OFFICE_EXTERNAL_AUTOLOAD",
                "loads external content when the document is opened")
    if unc:
        return ("office-external-relationship", Severity.MEDIUM, "OFFICE_EXTERNAL_NETWORK_PATH",
                "points to a network/file path; opening it can leak Windows credentials")
    if rel_type == "hyperlink" and scheme in ("http", "https", "mailto"):
        return None  # ordinary clickable link
    return ("office-external-relationship", Severity.INFO, "OFFICE_EXTERNAL_RESOURCE",
            "references an external resource")


def scan_ooxml(data: bytes) -> list[Finding]:
    found: list[Finding] = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()

        # Structure and resource checks before any member is decompressed.
        if len(infos) > MAX_ZIP_ENTRIES:
            return [finding("office-package-abuse", Severity.HIGH,
                            f"Package has {len(infos)} entries (limit {MAX_ZIP_ENTRIES}); likely resource abuse.",
                            "OFFICE_ZIP_TOO_MANY_ENTRIES")]
        total = sum(i.file_size for i in infos)
        if total > MAX_TOTAL_UNCOMPRESSED:
            return [finding("office-package-abuse", Severity.HIGH,
                            f"Package declares {total // 2**20} MB of uncompressed content from a "
                            f"{len(data) // 2**20 or '<1'} MB file; likely a decompression bomb.",
                            "OFFICE_ZIP_DECOMPRESSION_BOMB")]
        unsafe = [i.filename for i in infos if unsafe_member_name(i.filename)]
        if unsafe:
            found.append(finding("office-package-abuse", Severity.HIGH,
                                 f"Package contains path-traversal or absolute member names "
                                 f"(e.g. {clean(unsafe[0], 60)!r}); never part of a legitimate document.",
                                 "OFFICE_ZIP_PATH_TRAVERSAL"))
        duplicates = [n for n, c in Counter(i.filename.lower() for i in infos).items() if c > 1]
        if duplicates:
            found.append(finding("office-package-abuse", Severity.MEDIUM,
                                 f"Package contains duplicate member names (e.g. {clean(duplicates[0], 60)!r}); "
                                 "different readers may see different content.", "OFFICE_ZIP_DUPLICATE_ENTRY"))
        encrypted = [i for i in infos if i.flag_bits & 0x1]
        if encrypted:
            found.append(finding("office-package-abuse", Severity.MEDIUM,
                                 "Package contains ZIP-encrypted members that cannot be inspected.",
                                 "OFFICE_ZIP_ENCRYPTED_ENTRY"))

        readable = [i for i in infos if not (i.flag_bits & 0x1) and not unsafe_member_name(i.filename)]
        names = {i.filename.lower(): i for i in readable}

        # Macros
        for lname, info in names.items():
            if lname.endswith("vbaproject.bin"):
                found += vba_findings(read_member(zf, info), "vbaProject.bin", has_vba_storage=True)
        macrosheets = [n for n in names if n.startswith("xl/macrosheets/")]
        if macrosheets:
            found.append(finding("office-macro", Severity.MEDIUM,
                                 "Workbook contains Excel 4.0 (XLM) macro sheets.", "OFFICE_XLM_MACROSHEET"))

        # ActiveX
        activex = [n for n in names if re.search(r"(^|/)activex/activex\d*\.(xml|bin)$", n)]
        if activex:
            found.append(finding("office-activex", Severity.MEDIUM,
                                 f"Document contains {len(activex)} ActiveX control part(s).", "OFFICE_ACTIVEX"))

        # Embedded OLE objects
        for lname, info in names.items():
            if "/embeddings/" in lname and lname.endswith(".bin"):
                blob = read_member(zf, info)
                where = f"Embedded object {clean(info.filename.rsplit('/', 1)[-1], 40)!r}"
                if blob.startswith(OLE_MAGIC):
                    with olefile.OleFileIO(blob) as ole:
                        objects = ole_object_findings(ole, where)
                    found += objects or [finding("office-embedded-object", Severity.LOW,
                                                 "Document contains an embedded OLE object.", "OFFICE_EMBEDDED_OLE")]
                else:
                    found.append(finding("office-embedded-object", Severity.LOW,
                                         f"{where} is an embedded binary object.", "OFFICE_EMBEDDED_BINARY"))

        # Relationships (aggregated so a document with many links stays readable)
        external: dict[tuple, list[str]] = {}
        for lname, info in names.items():
            if not lname.endswith(".rels"):
                continue
            for el in iter_xml(zf, info):
                if local(el.tag) != "Relationship" or el.get("TargetMode", "").lower() != "external":
                    continue
                rel_type = el.get("Type", "").rsplit("/", 1)[-1]
                verdict = external_relationship(rel_type, el.get("Target", ""))
                if verdict:
                    external.setdefault((rel_type, *verdict), []).append(el.get("Target", ""))
        for (rel_type, category, severity, rule_id, why), targets in external.items():
            count = f"{len(targets)} external '{clean(rel_type, 30)}' relationships" if len(targets) > 1 \
                else f"An external '{clean(rel_type, 30)}' relationship"
            found.append(finding(category, severity, f"{count} {why} (e.g. {clean(targets[0], 80)!r}).", rule_id))

        # DDE in Word fields
        for lname, info in names.items():
            if WORD_FIELD_PARTS.match(lname):
                found += word_dde_findings(iter_xml(zf, info))
        # DDE links in Excel external links
        for lname, info in names.items():
            if lname.startswith("xl/externallinks/") and lname.endswith(".xml"):
                for el in iter_xml(zf, info):
                    if local(el.tag) == "ddeLink":
                        service = el.get("ddeService", "")
                        dangerous = service.strip().lower().removesuffix(".exe") in DDE_SERVICES_RUNNING_COMMANDS
                        found.append(finding("office-dde", Severity.HIGH if dangerous else Severity.MEDIUM,
                                             f"Workbook contains a DDE link to application {clean(service, 40)!r}"
                                             f"{', which can run commands' if dangerous else ''}.",
                                             "OFFICE_DDE_LINK"))
    return found


def word_dde_findings(elements) -> list[Finding]:
    """Reassemble field instructions (often split across runs) and look for DDE/DDEAUTO."""
    instructions, current = [], None
    for el in elements:
        tag = local(el.tag)
        if tag == "fldChar":
            kind = next((v for k, v in el.attrib.items() if local(k) == "fldCharType"), "")
            if kind == "begin":
                current = []
            elif current is not None:
                instructions.append("".join(current))
                current = None
        elif tag == "instrText" and current is not None:
            current.append(el.text or "")
        elif tag == "fldSimple":
            instructions.append(next((v for k, v in el.attrib.items() if local(k) == "instr"), ""))

    found = []
    for instr in instructions:
        m = re.match(r"\s*(DDEAUTO|DDE)\b", instr, re.IGNORECASE)
        if m:
            auto = m.group(1).upper() == "DDEAUTO"
            found.append(finding("office-dde", Severity.HIGH if auto else Severity.MEDIUM,
                                 f"Document contains a {m.group(1).upper()} field"
                                 f"{' that runs when the document is opened' if auto else ''}: {clean(instr, 80)!r}.",
                                 "OFFICE_DDEAUTO_FIELD" if auto else "OFFICE_DDE_FIELD"))
    return found
