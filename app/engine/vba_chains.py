"""VBA call graphs: can an automatically running procedure reach a dangerous operation?

The custom engine's own analysis (FilesMagic capstone). Reused from oletools/olevba (0.60.2):
source extraction (VBA_Parser.extract_macros), line-continuation handling
(vba_collapse_long_lines), the definition of automatic entry points (AUTOEXEC_KEYWORDS,
AUTOEXEC_KEYWORDS_REGEX) and keyword analysis (VBA_Scanner). Reused from the Office scanner: what
counts as a dangerous capability (STRONG_VBA_BEHAVIOUR), format identification and ZIP limits.

New here: procedures, a call graph between them and a search from every entry point. Per entry,
one of three outcomes:
  linked        a chain of calls reaches a procedure with a dangerous capability (path recorded)
  no-path       no such chain exists in the source, and the source was analysed completely
  undetermined  no chain was found, but the source could hide one: a dynamic call (Run with a
                computed name, CallByName, Evaluate, self-modifying code) on the reachable part,
                unbalanced procedure blocks, a capability outside any procedure, a capability or
                entry keyword olevba reports that no procedure accounts for, XLM macros, or a
                VBA project that could not be read
Errors go one way: names are matched loosely (a variable that shares a procedure's name becomes
an edge), so a chain may be over-reported, never hidden.

"no-path" is a statement about the source only. Office may execute the compiled P-code instead,
and VBA stomping replaces the source while keeping malicious P-code. olevba checks that only for
files on disk (VBA_Parser.detect_vba_stomping); the isolated worker never writes files. So
app.engine.correlate never lowers a reference finding on "no-path"; it only reports it.

Nothing is executed. Inputs are bounded by the Office scanner's limits and MAX_SOURCE_BYTES.
"""

import io
import re
import zipfile
from collections import deque
from dataclasses import dataclass, field

from oletools.olevba import AUTOEXEC_KEYWORDS, AUTOEXEC_KEYWORDS_REGEX, VBA_Parser, VBA_Scanner, vba_collapse_long_lines

from app.scanners import office
from app.scanners.base import ScanError

LINKED, NO_PATH, UNDETERMINED = "linked", "no-path", "undetermined"
MAX_SOURCE_BYTES = 8 * 1024 * 1024  # all modules of a document together
MAX_PROCEDURES = 20_000

_START = re.compile(r"^\s*(?:(?:Public|Private|Friend|Static)\s+)*(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+"
                    r"([A-Za-z_]\w*)", re.I)
_END = re.compile(r"^\s*End\s+(?:Sub|Function|Property)\b", re.I)
_DECLARE = re.compile(r"^\s*(?:(?:Public|Private)\s+)?Declare\s+(?:PtrSafe\s+)?(?:Sub|Function)\s+([A-Za-z_]\w*)", re.I)
_IDENT = re.compile(r"[A-Za-z_]\w*")
# Calls that name their target in a string, so a literal naming a procedure resolves them.
_NAMED_DISPATCH = re.compile(r"\b(Run|OnTime|OnKey|OnAction|CallByName|MacroRun)\b", re.I)
# Calls whose target cannot be known statically, and self-modifying code.
_DYNAMIC = re.compile(r"\b(Evaluate|ExecuteExcel4Macro|VBProject|VBComponents|CodeModule|InsertLines|AddFromString"
                      r"|AddFromFile|ReplaceLine|ExecuteGlobal|ExecuteStatement)\b", re.I)
_ADDRESS_OF = re.compile(r"\bAddressOf\s+(?:[A-Za-z_]\w*\.)?([A-Za-z_]\w*)", re.I)
_ENTRY_NAMES = {k.lower() for keywords in AUTOEXEC_KEYWORDS.values() for k in keywords}
_ENTRY_PATTERNS = [re.compile(rf"(?i)^{p}$") for patterns in AUTOEXEC_KEYWORDS_REGEX.values() for p in patterns]


class VbaChainError(ScanError):
    malformed_causes = office.OfficeScanError.malformed_causes


@dataclass
class Procedure:
    module: str
    name: str
    text: str = ""  # original source, for keyword analysis
    code: list[tuple[str, list[str]]] = field(default_factory=list)  # (cleaned line, its literals)
    capabilities: list[str] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class EntryResult:
    entry: str
    outcome: str
    path: tuple[str, ...] = ()  # entry ... procedure with the capability (linked only)
    capabilities: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()  # why undetermined


@dataclass
class VbaChains:
    entries: list[EntryResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # project-wide reasons for undetermined

    @property
    def outcome(self) -> str:
        outcomes = {e.outcome for e in self.entries}
        return LINKED if LINKED in outcomes else UNDETERMINED if UNDETERMINED in outcomes or self.problems else NO_PATH


def strong(code: str) -> list[str]:
    """olevba's suspicious-keyword descriptions in `code` that the Office scanner rates strong."""
    return sorted({office.clean(desc, 90) for kind, _, desc in VBA_Scanner(code).scan()
                   if kind == "Suspicious" and office.STRONG_VBA_BEHAVIOUR.search(desc)})


def _clean(line: str) -> tuple[str, list[str]]:
    """The line without its comment and with string contents blanked (each string becomes ""),
    and the string literals of its code part, in order. Literals in a comment are not returned,
    so a comment cannot resolve a dynamic call."""
    out, literals, i, current = [], [], 0, None  # current: characters of the open string, or None
    while i < len(line):
        c = line[i]
        if current is not None:
            if c == '"' and line[i + 1:i + 2] == '"':  # "" inside a string is one quote
                current.append('"')
                i += 1
            elif c == '"':
                literals.append("".join(current))
                out.append('""')
                current = None
            else:
                current.append(c)
        elif c == '"':
            current = []
        elif c == "'" or (re.match(r"(?i)rem\b", line[i:i + 4]) and not "".join(out).strip(" \t:")):
            break  # comment to the end of the line ("Rem" only where a statement starts)
        else:
            out.append(c)
        i += 1
    return "".join(out), literals


def parse(module: str, source: str, problems: list[str]) -> tuple[list[Procedure], str]:
    """Procedures of one module and the text outside them (declarations)."""
    procedures, outside, current = [], [], None
    for raw in vba_collapse_long_lines(source).splitlines():
        line, literals = _clean(raw)
        if declared := _DECLARE.match(line):
            procedures.append(Procedure(module, declared.group(1), raw, [(line, literals)]))
            continue
        if start := _START.match(line):
            if current:
                problems.append(f"{module}: {current.name} has no End before {start.group(1)} starts")
                procedures.append(current)
            current = Procedure(module, start.group(1))
        if current:
            current.text += raw + "\n"
            current.code.append((line, literals))
            if _END.match(line):
                procedures.append(current)
                current = None
        else:
            outside.append(raw)
            if _END.match(line):
                problems.append(f"{module}: End without a procedure")
    if current:
        problems.append(f"{module}: {current.name} is never ended")
        procedures.append(current)
    return procedures, "\n".join(outside)


def _target(literal: str) -> str:
    """'Book.xlsm'!Module1.Proc -> proc"""
    return literal.rsplit("!", 1)[-1].rsplit(".", 1)[-1].strip().lower()


def analyse(modules: list[tuple[str, str]], problems: list[str] | None = None) -> VbaChains:
    """modules: (module name, VBA source). `problems`: reasons found while extracting them."""
    result = VbaChains(problems=list(problems or []))
    procedures = []
    for module, source in modules:
        procs, outside = parse(module, source, result.problems)
        procedures += procs
        if found := strong(outside):
            result.problems.append(f"{module}: dangerous keywords outside any procedure ({'; '.join(found)})")
        located = set(strong("\n".join(p.text for p in procs)))
        if missing := sorted(set(strong(source)) - located - set(found)):
            result.problems.append(f"{module}: olevba reports {'; '.join(missing)} but no procedure accounts for it")
    if len(procedures) > MAX_PROCEDURES:
        raise VbaChainError(f"VBA project has more than {MAX_PROCEDURES} procedures")

    by_name: dict[str, list[Procedure]] = {}
    for p in procedures:
        p.capabilities = strong(p.text)
        by_name.setdefault(p.name.lower(), []).append(p)

    edges, dynamic = {}, {}
    for p in procedures:
        targets, reasons = set(), []
        for line, literals in p.code[1:]:  # the first line declares the procedure itself
            targets |= {n.lower() for n in _IDENT.findall(line)} & by_name.keys()
            targets |= {m.group(1).lower() for m in _ADDRESS_OF.finditer(line)} & by_name.keys()
            if m := _DYNAMIC.search(line):
                reasons.append(f"{p.label} uses {m.group(1)}")
            if m := _NAMED_DISPATCH.search(line):
                named = {_target(lit) for lit in literals} & by_name.keys()
                targets |= named
                if not named:
                    reasons.append(f"{p.label} calls {m.group(1)} with a name that is not a known procedure")
        edges[p.label] = [q for name in targets for q in by_name[name]]
        dynamic[p.label] = reasons

    entries = [p for p in procedures if p.name.lower() in _ENTRY_NAMES or any(r.match(p.name) for r in _ENTRY_PATTERNS)]
    defined = {p.name.lower() for p in entries}
    for module, source in modules:
        for kind, keyword, _ in VBA_Scanner(source).scan():
            if kind == "AutoExec" and keyword.lower() not in defined:
                result.problems.append(f"{module}: automatic-entry keyword {office.clean(keyword, 40)!r} "
                                       "is not a procedure this analysis found")

    for entry in entries:
        parent, queue, reasons, found = {entry.label: None}, deque([entry]), [], None
        while queue and not found:
            p = queue.popleft()
            if p.capabilities:
                found = p
                break
            reasons += dynamic[p.label]
            for q in edges[p.label]:
                if q.label not in parent:
                    parent[q.label] = p.label
                    queue.append(q)
        if found:
            path, node = [], found.label
            while node:
                path.append(node)
                node = parent[node]
            result.entries.append(EntryResult(entry.label, LINKED, tuple(reversed(path)), tuple(found.capabilities)))
        elif reasons or result.problems:
            result.entries.append(EntryResult(entry.label, UNDETERMINED, reasons=tuple(dict.fromkeys(reasons))))
        else:
            result.entries.append(EntryResult(entry.label, NO_PATH))
    return result


# ----------------------------------------------------------------------------- documents


def projects(data: bytes) -> list[tuple[str, bytes]] | None:
    """The VBA containers of an Office document: the file itself (legacy OLE) or each
    vbaProject.bin part (OOXML), with the Office scanner's limits. None: not an Office file."""
    kind = office.identify(data)
    if kind is None:
        return None
    if kind == "ole":
        return [("document", data)]
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > office.MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > office.MAX_TOTAL_UNCOMPRESSED:
            raise VbaChainError("package exceeds the Office scanner's ZIP limits")
        return [(i.filename, office.read_member(zf, i)) for i in infos
                if i.filename.lower().endswith("vbaproject.bin") and not i.flag_bits & 0x1
                and not office.unsafe_member_name(i.filename)]


def scan(data: bytes) -> VbaChains | None:
    """None if this is not an Office document or it has no VBA project."""
    try:
        containers = projects(data)
    except (zipfile.BadZipFile, office.OfficeScanError) as e:
        # A broken ZIP is malformed input; the Office scanner's own limit checks have no cause.
        cause = e if isinstance(e, zipfile.BadZipFile) else e.__cause__
        raise VbaChainError(f"Office container could not be read: {office.clean(e, 200)}") from cause
    if containers is None:
        return None
    modules, problems, total = [], [], 0
    for label, blob in containers:
        if not blob.startswith(office.OLE_MAGIC):
            problems.append(f"{office.clean(label, 60)} is not an OLE VBA project")
            continue
        parser = VBA_Parser(label, data=blob)
        try:
            if parser.detect_xlm_macros():
                problems.append("Excel 4.0 (XLM) macros are present; they are not part of this call graph")
            if not parser.detect_vba_macros():
                continue
            for _, _, name, code in parser.extract_macros():
                total += len(code or "")
                if total > MAX_SOURCE_BYTES:
                    raise VbaChainError(f"VBA source exceeds {MAX_SOURCE_BYTES} bytes")
                modules.append((office.clean(name or "module", 40), code or ""))
        except VbaChainError:
            raise
        except Exception as e:
            problems.append(f"{office.clean(label, 60)} could not be extracted ({type(e).__name__})")
        finally:
            parser.close()
    return analyse(modules, problems) if modules or problems else None
