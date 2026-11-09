"""Word field codes (C7): DDE, DDEAUTO, INCLUDETEXT and INCLUDEPICTURE in WordprocessingML.

Static only: field instructions are read as text from the XML. Nothing is evaluated, updated or
fetched, and no nested field is computed.

Where fields live (ECMA-376 Part 1, 17.16): a simple field is w:fldSimple with the instruction in
w:instr. A complex field is w:fldChar begin, then the instruction in w:instrText runs (split
across any number of runs, w:delInstrText inside a tracked deletion), then optionally w:fldChar
separate and the last displayed result, then w:fldChar end. Fields nest. A nested field inside an
instruction is replaced by NESTED, because its result exists only once Word updates it (the
QUOTE-field obfuscation of DDE builds the command that way). Only the two WordprocessingML
namespaces (transitional and strict) are read, in every XML part Office reaches through
relationships (ooxml_links.loaded_parts): body, headers, footers, notes, comments, glossary.

Instruction syntax (17.16.1): the field type is the first token, case-insensitive. Arguments are
words or "quoted text"; inside both, \\ stands for one backslash (so Word writes c:\\\\windows in
the XML for c:\\windows) and \\" for a quote. A token that begins with one backslash is a switch
(\\d, \\* MERGEFORMAT); the arguments considered are the tokens before the first switch.

Classification. Severity follows what the evidence shows the field can do, not that Word will
do it: Word asks before it updates links or starts a DDE server, and the defaults differ by version
and policy (Microsoft ADV170021 turned DDE off by default).
  ENGINE_WORD_DDEAUTO_PROGRAM   HIGH    DDEAUTO (an automatic link, updated when the document opens)
                                        whose application is a program: a path, an executable or
                                        script extension, a command interpreter or script host, or
                                        built by a nested field
  ENGINE_WORD_DDE_PROGRAM       MEDIUM  the same with DDE (updated when fields are updated)
  ENGINE_WORD_DDE_APPLICATION   LOW     DDE or DDEAUTO naming a DDE server by name (e.g. Excel):
                                        a data link to another application, which Word may start
  ENGINE_WORD_REMOTE_INCLUDE    MEDIUM  INCLUDETEXT whose source names a host (a URL, UNC, a file
                                        URI with a host, another scheme) or is built by a nested
                                        field: the included document's text and fields become part
                                        of this one; INCLUDEPICTURE from a network file path, other
                                        scheme or nested field (a UNC lookup can send the user's
                                        Windows credentials, as OFFICE_EXTERNAL_NETWORK_PATH)
  ENGINE_WORD_WEB_PICTURE       INFO    INCLUDEPICTURE from http(s)/ftp: what Word itself writes for
                                        pictures pasted from a web page; a web beacon at most, as
                                        ENGINE_OFFICE_LINKED_PICTURE
  ENGINE_WORD_LOCAL_INCLUDE     INFO    INCLUDETEXT or INCLUDEPICTURE from a drive path naming no
                                        host (app.engine.file_paths) or a relative path
  ENGINE_WORD_FIELDS_UNDETERMINED INFO  a loaded part could not be read or parsed, a field type is
                                        itself built by a nested field, or an imported chunk
                                        (w:altChunk) is present, which C7 does not analyse
INCLUDE and IMPORT, the old names of INCLUDETEXT and INCLUDEPICTURE, are treated as those.
Every other field type (PAGE, TOC, HYPERLINK, MERGEFIELD, ...) is not reported.

Relation to the reference Office scanner, which reports any DDEAUTO (OFFICE_DDEAUTO_FIELD, HIGH)
and DDE (OFFICE_DDE_FIELD, MEDIUM) in word/document, header, footer, footnotes and endnotes parts
by name. C7 is additive: it accounts for no reference finding, so those stand in the unified engine
whatever C7 concludes (a DDEAUTO to Excel stays HIGH there). What C7 adds: a DDE instruction built
by a nested field (the reference reassembly restarts at the nested begin and loses the outer
type), instruction text in tracked deletions, parts Word loads under other names (comments,
glossary, a header stored as word/parts/h.xml), INCLUDETEXT and INCLUDEPICTURE with their targets,
and which application a DDE field names. It ignores parts Word never loads (the reference does not).
"""

import io
import re
from dataclasses import dataclass, field

import defusedxml.ElementTree as SafeET

from app.engine import ooxml_links
from app.engine.correlate import finding
from app.engine.file_paths import local_drive_path
from app.models import Finding, Severity
from app.scanners.custom import ooxml_package as opc
from app.scanners.custom.indicators import clean, listing
from app.scanners.custom.ooxml import is_xml

NAME = "word-fields"
CATEGORY = "office-field-code"
W_NS = {"http://schemas.openxmlformats.org/wordprocessingml/2006/main", "http://purl.oclc.org/ooxml/wordprocessingml/main"}
NESTED = "\ufffc"  # where a nested field's result goes: unknown until Word updates the field
ALIASES = {"INCLUDE": "INCLUDETEXT", "IMPORT": "INCLUDEPICTURE"}
INTERPRETERS = {"cmd", "command", "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32",
                "msiexec", "certutil", "bitsadmin", "schtasks", "wmic", "forfiles", "conhost", "explorer", "hh",
                "msbuild", "installutil", "bash", "sh", "python", "pythonw"}
PROGRAM_EXTENSIONS = {"exe", "com", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "scr", "pif",
                      "cpl", "msi", "lnk", "dll"}
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")

RULES = {  # rule -> (severity, summary)
    "ENGINE_WORD_DDEAUTO_PROGRAM": (Severity.HIGH, "A DDEAUTO field, updated when the document opens, names a program "
                                    "or command interpreter as its application: it asks Word to start that program."),
    "ENGINE_WORD_DDE_PROGRAM": (Severity.MEDIUM, "A DDE field names a program or command interpreter as its "
                                "application: updating the field asks Word to start that program."),
    "ENGINE_WORD_DDE_APPLICATION": (Severity.LOW, "A DDE field links to data in another application, which Word may "
                                    "start when the link is updated."),
    "ENGINE_WORD_REMOTE_INCLUDE": (Severity.MEDIUM, "An include field takes content from a host-named location, a "
                                   "network file path or a location built by a nested field (included text can bring "
                                   "further fields; a network path lookup can send the user's Windows credentials)."),
    "ENGINE_WORD_WEB_PICTURE": (Severity.INFO, "An INCLUDEPICTURE field shows a picture from the web, as Word writes for "
                                "pictures pasted from a web page; if fetched, that server learns the document was "
                                "opened."),
    "ENGINE_WORD_LOCAL_INCLUDE": (Severity.INFO, "An include field takes content from a drive or relative path that "
                                  "names no host; that file is outside this document and was not inspected."),
    "ENGINE_WORD_FIELDS_UNDETERMINED": (Severity.INFO, "Some field codes could not be determined."),
}


@dataclass(frozen=True)
class Field:
    part: str  # as stored in the ZIP
    instruction: str  # NESTED where a nested field's result goes
    deleted: bool = False  # instruction text in a tracked deletion


@dataclass
class _Open:
    text: list[str] = field(default_factory=list)
    instruction: bool = True  # until fldChar separate
    deleted: bool = False


def fields(data: bytes, part: str = "") -> list[Field]:
    """Every field instruction in one XML part, outermost last. Raises opc.MALFORMED."""
    out: list[Field] = []
    stack: list[_Open] = []

    def close(f: _Open) -> None:
        out.append(Field(part, "".join(f.text), f.deleted))

    for event, el in SafeET.iterparse(io.BytesIO(data), events=("start", "end"), forbid_dtd=True):
        ns, tag = ooxml_links._local(el.tag)
        if ns not in W_NS:
            if event == "end":
                el.clear()
            continue
        if event == "start":
            if tag == "fldSimple":
                out.append(Field(part, el.get(f"{{{ns}}}instr", "")))
            elif tag == "fldChar":
                kind = el.get(f"{{{ns}}}fldCharType")
                if kind == "begin":
                    if stack and stack[-1].instruction:
                        stack[-1].text.append(NESTED)
                    stack.append(_Open())
                elif kind == "separate" and stack:
                    stack[-1].instruction = False
                elif kind == "end" and stack:
                    close(stack.pop())
        else:
            if tag in ("instrText", "delInstrText") and stack and stack[-1].instruction:
                stack[-1].text.append(el.text or "")
                stack[-1].deleted |= tag == "delInstrText"
            el.clear()
    for f in reversed(stack):  # ponytail: an unterminated field is read as far as it goes
        close(f)
    return out


def tokens(instruction: str) -> list[str]:
    """The tokens before the first switch, with \\\\ and \\" unescaped."""
    out, i, n = [], 0, len(instruction)
    while i < n:
        c = instruction[i]
        if c.isspace():
            i += 1
            continue
        if c == "\\" and instruction[i + 1:i + 2] not in ("\\", '"', ""):
            break  # a switch: the arguments end here
        quoted = c == '"'
        i += quoted
        buf = []
        while i < n and (instruction[i] != '"' if quoted else not instruction[i].isspace() and instruction[i] != '"'):
            if instruction[i] == "\\" and i + 1 < n and instruction[i + 1] in '\\"':
                i += 1
            buf.append(instruction[i])
            i += 1
        i += quoted and i < n
        out.append("".join(buf))
    return out


def is_program(app: str) -> bool:
    """Does a DDE application name a program rather than a DDE server name? Built by a nested
    field counts as a program: what Word would start is not known. Empty: nothing is named."""
    if NESTED in app:
        return True
    if not app.strip():
        return False
    base = re.split(r"[\\/]", app.strip())[-1].lower()
    stem, _, ext = base.rpartition(".")
    return "\\" in app or "/" in app or ":" in app or ext in PROGRAM_EXTENSIONS or (stem or base) in INTERPRETERS


def target_class(target: str | None) -> str:
    """missing, nested, local (drive path naming no host, or relative), web (http/https/ftp), or
    network (UNC, file URI that is not a local drive path, any other scheme)."""
    if target is None or not target.strip():
        return "missing"
    if NESTED in target:
        return "nested"
    t = target.strip()
    if local_drive_path(t):
        return "local"
    low = t.lower()
    if low.startswith(("http://", "https://", "ftp://")):
        return "web"
    if t.startswith(("\\\\", "//")) or _SCHEME.match(t):
        return "network"
    return "local"  # relative or rooted: resolved against the document's own location


def classify(f: Field) -> tuple[str, str] | None:
    """(rule, evidence) for one field, or None if its type is not one C7 reports."""
    words = tokens(f.instruction)
    if not words:
        return None
    kind = ALIASES.get(words[0].upper(), words[0].upper())
    shown = clean(f.instruction.replace(NESTED, "{nested field}").strip(), 200)
    where = f"{f.part}{' (tracked deletion)' if f.deleted else ''}: {shown}"
    if NESTED in words[0]:
        return "ENGINE_WORD_FIELDS_UNDETERMINED", f"{where} (field type built by a nested field)"
    if kind in ("DDE", "DDEAUTO"):
        app = words[1] if len(words) > 1 else ""
        if is_program(app):
            return ("ENGINE_WORD_DDEAUTO_PROGRAM" if kind == "DDEAUTO" else "ENGINE_WORD_DDE_PROGRAM"), where
        return "ENGINE_WORD_DDE_APPLICATION", where
    if kind in ("INCLUDETEXT", "INCLUDEPICTURE"):
        cls = target_class(words[1] if len(words) > 1 else None)
        if cls == "missing":
            return None  # includes nothing
        if cls == "local":
            return "ENGINE_WORD_LOCAL_INCLUDE", where
        if cls == "web" and kind == "INCLUDEPICTURE":
            return "ENGINE_WORD_WEB_PICTURE", where
        return "ENGINE_WORD_REMOTE_INCLUDE", f"{where} ({'built by a nested field' if cls == 'nested' else cls})"
    return None


@dataclass
class WordFields:
    fields: list[Field] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def scan(data: bytes) -> WordFields | None:
    """None unless this is a Word package. Raises CustomScanError (fail closed) when its content
    types or relationship parts cannot be read."""
    package = opc.open_package(data)
    if package is None:
        return None
    main = opc.main_document(package)
    if not main.part or not any(k in (main.content_type or "") for k in ("wordprocessingml", "ms-word")):
        return None
    result = WordFields()
    for part, (_, rel_type) in ooxml_links.loaded_parts(package).items():
        if not part or part not in package.parts:
            continue
        name = package.name(part)
        if rel_type.lower() == "afchunk":  # w:altChunk: Word imports this part (RTF, HTML, a document)
            result.problems.append(f"{name} is an imported chunk (altChunk), whose fields are not analysed")
            continue
        if not is_xml(package, part):
            continue
        body = package.read(part, opc.MAX_PART_BYTES, required=False)
        if body is None:
            result.problems.append(f"{name} could not be read")
            continue
        try:
            result.fields += fields(body, name)
        except opc.MALFORMED:
            result.problems.append(f"{name} is not well-formed XML")
    return result


def findings(result: WordFields) -> list[Finding]:
    by: dict[str, list[str]] = {}
    for f in result.fields:
        if hit := classify(f):
            by.setdefault(hit[0], []).append(hit[1])
    if result.problems:
        by.setdefault("ENGINE_WORD_FIELDS_UNDETERMINED", []).extend(result.problems)
    return [finding(rule, RULES[rule][0], f"{RULES[rule][1]} Evidence: {listing(items)}.", scanner=NAME,
                    category=CATEGORY, evidence=items) for rule, items in by.items()]


class FieldScanner:
    name = NAME

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        result = scan(data)
        return None if result is None else findings(result)
