"""VBA call graphs: is there a demonstrated path from an automatic procedure to a dangerous operation?

The custom engine's own analysis (FilesMagic capstone). Reused from oletools/olevba (0.60.2):
source extraction (VBA_Parser.extract_macros), line-continuation handling
(vba_collapse_long_lines), the definition of automatic entry points (AUTOEXEC_KEYWORDS,
AUTOEXEC_KEYWORDS_REGEX) and keyword analysis (VBA_Scanner). Reused from the Office scanner: what
counts as a dangerous capability (STRONG_VBA_BEHAVIOUR), format identification and ZIP limits.

New here: procedures, a call graph whose edges and capabilities are each either DEMONSTRATED or
only POSSIBLE, and a search from every entry point.

Capabilities are olevba's strong keyword findings on the procedure's code without comments.
Demonstrated: at least one triggering keyword is specific (Shell, ShellExecuteA, InvokeVerb, ...),
or an ambiguous one is confirmed by its context in the same procedure (WScript.Shell with .Run or
.Exec; Create with Win32_Process). Possible: only AMBIGUOUS keywords (Application.Run starts
macros, shell32 is a library name, vbHide is an argument, Create and DoIt are common names, ...).

An occurrence of a procedure's name is a demonstrated call when it is a statement or `Call`
target, a function call in an expression, `Module.Name` with a known module, `AddressOf Name`, or
a string literal naming it in Run/OnTime/OnKey/OnAction/CallByName. It is only a possible call
when the name is also declared as a variable, constant or parameter (in the procedure, or at
module level anywhere), or when it is `obj.Name` on something that is not a module. A name after
`As`/`New`, or a named argument (`name:=`), is no call.

Per entry, one of three outcomes:
  linked        demonstrated calls reach a demonstrated capability (path recorded)
  no-path       nothing dangerous is reachable even through possible calls, and the source was
                analysed completely
  undetermined  anything else: a path that needs a possible call or ends in a possible
                capability, a dynamic call (OnKey with a computed name, CallByName, Evaluate,
                self-modifying code) on the reachable part, unbalanced procedure blocks, a
                capability outside any procedure, a capability or entry keyword olevba reports
                that no procedure accounts for, XLM macros, or a VBA project that could not be read

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
DEMONSTRATED, POSSIBLE = "demonstrated", "possible"
MAX_SOURCE_BYTES = 8 * 1024 * 1024  # all modules of a document together
MAX_PROCEDURES = 20_000

# olevba keywords that do not by themselves show that anything is executed.
AMBIGUOUS = {
    "shell": "Shell is also part of the object names WScript.Shell and Shell.Application",
    "run": "Run also starts macros (Application.Run); only a shell object's Run executes a command",
    "create": "Create is a common method name; it executes something only on WMI's Win32_Process",
    "doit": "DoIt is a common procedure name",
    "shell32": "shell32 is a library with many harmless functions",
    "wscript.shell": "WScript.Shell also reads special folders and the registry",
    **dict.fromkeys(["vbnormal", "vbnormalfocus", "vbhide", "vbminimizedfocus", "vbmaximizedfocus",
                     "vbnormalnofocus", "vbminimizednofocus"], "a window-style constant is an argument, not a call"),
}
# Ambiguous keyword -> (context in the same procedure that confirms it, searched with strings intact?).
CONFIRMED_BY = {
    "shell": (re.compile(r"(?<![.\w])Shell\b(?!\s*\.)", re.I), False),  # the Shell function, in code
    "wscript.shell": (re.compile(r"\.\s*(?:Run|Exec)\b", re.I), False),
    "create": (re.compile(r"Win32_Process", re.I), True),
}

_START = re.compile(r"^\s*(?:(?:Public|Private|Friend|Static)\s+)*(?:Sub|Function|Property\s+(?:Get|Let|Set))\s+"
                    r"([A-Za-z_]\w*)\s*(?:\((.*)\))?", re.I)
_END = re.compile(r"^\s*End\s+(?:Sub|Function|Property)\b", re.I)
_DECLARE = re.compile(r"^\s*(?:(?:Public|Private)\s+)?Declare\s+(?:PtrSafe\s+)?(?:Sub|Function)\s+([A-Za-z_]\w*)", re.I)
# Variable and constant declarations (not Sub/Function/Property/Declare/Type/Enum/Event statements).
_DIM = re.compile(r"^\s*(?:(?:Public|Private|Global|Friend|Dim|Static|ReDim|Preserve|Const)\s+)+"
                  r"(?!(?:Sub|Function|Property|Declare|Type|Enum|Event)\b)(.+)", re.I)
_FOR = re.compile(r"\bFor\s+(?:Each\s+)?([A-Za-z_]\w*)", re.I)
_ENUM, _END_ENUM = re.compile(r"^\s*(?:(?:Public|Private)\s+)?Enum\b", re.I), re.compile(r"^\s*End\s+Enum\b", re.I)
_MODIFIERS = re.compile(r"^\s*(?:(?:Optional|ByVal|ByRef|ParamArray|WithEvents)\s+)*", re.I)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_STATEMENTS = re.compile(r":(?!=)|\bThen\b|\bElse\b", re.I)  # statement separators, incl. one-line If
# Calls that name their target in a string, so a literal naming a procedure resolves them.
_NAMED_DISPATCH = re.compile(r"\b(Run|OnTime|OnKey|OnAction|CallByName|MacroRun)\b", re.I)
# Calls whose target cannot be known statically, and self-modifying code.
_DYNAMIC = re.compile(r"\b(Evaluate|ExecuteExcel4Macro|VBProject|VBComponents|CodeModule|InsertLines|AddFromString"
                      r"|AddFromFile|ReplaceLine|ExecuteGlobal|ExecuteStatement)\b", re.I)
_ENTRY_NAMES = {k.lower() for keywords in AUTOEXEC_KEYWORDS.values() for k in keywords}
_ENTRY_PATTERNS = [re.compile(rf"(?i)^{p}$") for patterns in AUTOEXEC_KEYWORDS_REGEX.values() for p in patterns]


class VbaChainError(ScanError):
    malformed_causes = office.OfficeScanError.malformed_causes


@dataclass
class Procedure:
    module: str
    name: str
    params: str = ""  # the parameter list of its declaration line
    text: str = ""  # its code without comments (strings kept), for keyword analysis
    code: list[tuple[str, list[str]]] = field(default_factory=list)  # (line, strings blanked; its literals)
    demonstrated: list[str] = field(default_factory=list)  # capability descriptions with their keywords
    possible: list[str] = field(default_factory=list)
    edges: list[tuple["Procedure", str, str]] = field(default_factory=list)  # (callee, kind, why)
    dynamic: list[str] = field(default_factory=list)

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


def _strong(code: str) -> dict[str, set[str]]:
    """olevba's strong suspicious-keyword descriptions in `code`, with the keywords behind each."""
    found: dict[str, set[str]] = {}
    for kind, keyword, desc in VBA_Scanner(code).scan():
        if kind == "Suspicious" and office.STRONG_VBA_BEHAVIOUR.search(desc):
            found.setdefault(office.clean(desc, 90), set()).add(keyword.lower())
    return found


def strong(code: str) -> list[str]:
    return sorted(_strong(code))


def capabilities(code: str, blanked: str) -> tuple[list[str], list[str]]:
    """(demonstrated, possible) capabilities, each "description (keywords)". `code`: comment-free
    source; `blanked`: the same with string contents removed."""
    def confirmed(keyword: str) -> bool:
        pattern, in_strings = CONFIRMED_BY.get(keyword, (None, False))
        return bool(pattern and pattern.search(code if in_strings else blanked))

    demonstrated, possible = [], []
    for desc, keywords in sorted(_strong(code).items()):
        specific = {k for k in keywords if k not in AMBIGUOUS or confirmed(k)}
        if specific:
            demonstrated.append(f"{desc} ({', '.join(sorted(specific))})")
        else:
            possible.append(f"{desc} (only {', '.join(sorted(keywords))}: {AMBIGUOUS[min(keywords)]})")
    return demonstrated, possible


def _clean(line: str) -> tuple[str, list[str], str]:
    """(the line without its comment and with string contents blanked, each string becoming "";
    the string literals of its code part; the code part with strings intact). Literals in a
    comment are not returned, so a comment can neither resolve a call nor carry a keyword."""
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
    return "".join(out), literals, line[:i]


def _first_names(text: str) -> set[str]:
    """First identifier of each top-level comma-separated part ("a As Long, b(3), c = 1")."""
    names, depth, part = set(), 0, []
    for c in text + ",":
        depth += c == "("
        depth -= c == ")"
        if c == "," and depth <= 0:
            if m := _IDENT.match(_MODIFIERS.sub("", "".join(part))):
                names.add(m.group().lower())
            part = []
        else:
            part.append(c)
    return names


def declared(line: str) -> set[str]:
    """Names a cleaned line declares as variables, constants or loop counters."""
    names = {m.group(1).lower() for m in _FOR.finditer(line)}
    for statement in re.split(r":(?!=)", line):
        if m := _DIM.match(statement):
            names |= _first_names(m.group(1))
    return names


def parse(module: str, source: str, problems: list[str]) -> tuple[list[Procedure], str, set[str]]:
    """Procedures of one module, its comment-free text outside them, and the names that text declares."""
    procedures, outside, module_names, current, in_enum = [], [], set(), None, False
    for raw in vba_collapse_long_lines(source).splitlines():
        line, literals, code = _clean(raw)
        if declared_function := _DECLARE.match(line):
            procedures.append(Procedure(module, declared_function.group(1), "", code, [(line, literals)]))
            continue
        if start := _START.match(line):
            if current:
                problems.append(f"{module}: {current.name} has no End before {start.group(1)} starts")
                procedures.append(current)
            current = Procedure(module, start.group(1), start.group(2) or "")
        if current:
            current.text += code + "\n"
            current.code.append((line, literals))
            if _END.match(line):
                procedures.append(current)
                current = None
            continue
        outside.append(code)
        if _END.match(line):
            problems.append(f"{module}: End without a procedure")
        if _ENUM.match(line):
            in_enum = True
        elif _END_ENUM.match(line):
            in_enum = False
        elif in_enum and (m := _IDENT.match(line.strip())):
            module_names.add(m.group().lower())  # an Enum member is a constant
        else:
            module_names |= declared(line)
    if current:
        problems.append(f"{module}: {current.name} is never ended")
        procedures.append(current)
    return procedures, "\n".join(outside), module_names


def _target(literal: str) -> str:
    """'Book.xlsm'!Module1.Proc -> proc"""
    return literal.rsplit("!", 1)[-1].rsplit(".", 1)[-1].strip().lower()


def link(p: Procedure, by_name: dict[str, list[Procedure]], modules: dict[str, str], shadowed: set[str]) -> None:
    """Fill p.edges and p.dynamic from its code (see the module docstring for the rules)."""
    local = set(shadowed) | _first_names(p.params)
    for line, _ in p.code[1:]:
        local |= declared(line)
    own = p.name.lower()
    for line, literals in p.code[1:]:  # the first line declares the procedure itself
        if m := _DYNAMIC.search(line):
            p.dynamic.append(f"{p.label} uses {m.group(1)}")
        if m := _NAMED_DISPATCH.search(line):
            named = {_target(lit) for lit in literals} & by_name.keys()
            p.edges += [(q, DEMONSTRATED, f"named in a {m.group(1)} string") for n in named for q in by_name[n]]
            if not named:
                p.dynamic.append(f"{p.label} calls {m.group(1)} with a name that is not a known procedure")
        for statement in _STATEMENTS.split(line):
            for m in _IDENT.finditer(statement):
                name = m.group().lower()
                if name not in by_name or name == own:
                    continue
                before, after = statement[:m.start()].rstrip(), statement[m.end():].lstrip()
                previous = (_IDENT.findall(before) or [""])[-1].lower()
                if after.startswith(":=") or (previous in ("as", "new") and not before.endswith(".")):
                    continue  # a named argument or a type name: no call
                if before.endswith("."):
                    qualifier = (re.findall(r"([A-Za-z_]\w*)\s*\.$", before) or [""])[-1].lower()
                    in_module = [q for q in by_name[name] if q.module.lower() == qualifier]
                    if qualifier in modules and in_module:
                        p.edges += [(q, DEMONSTRATED, f"called as {modules[qualifier]}.{q.name}") for q in in_module]
                    else:
                        p.edges += [(q, POSSIBLE, f"'{m.group()}' is a member of something that is not a module")
                                    for q in by_name[name]]
                elif previous in ("call", "addressof") or name not in local:
                    p.edges += [(q, DEMONSTRATED, "called") for q in by_name[name]]
                else:
                    p.edges += [(q, POSSIBLE, f"'{m.group()}' is also declared as a variable, constant or parameter")
                                for q in by_name[name]]


def _path(parent: dict, node: str) -> tuple[str, ...]:
    path = []
    while node:
        path.append(node)
        node = parent[node][0]
    return tuple(reversed(path))


def search(entry: Procedure, problems: list[str]) -> EntryResult:
    # 1. Demonstrated calls only, to a demonstrated capability.
    parent, queue = {entry.label: (None, "")}, deque([entry])
    while queue:
        p = queue.popleft()
        if p.demonstrated:
            return EntryResult(entry.label, LINKED, _path(parent, p.label), tuple(p.demonstrated))
        for q, kind, _ in p.edges:
            if kind == DEMONSTRATED and q.label not in parent:
                parent[q.label] = (p.label, "")
                queue.append(q)
    # 2. Every call: anything dangerous, or unknowable, that a possible call or capability could reach.
    parent, queue, reasons = {entry.label: (None, "")}, deque([entry]), []
    while queue:
        p = queue.popleft()
        doubt = next((why for _, why in (parent[n] for n in _path(parent, p.label)) if why), "")
        if p.demonstrated or p.possible:
            route = " -> ".join(_path(parent, p.label))
            reasons.append(f"possible path {route}: " + (doubt if doubt else "; ".join(p.possible)))
        reasons += p.dynamic
        for q, kind, why in p.edges:
            if q.label not in parent:
                parent[q.label] = (p.label, why if kind == POSSIBLE else "")
                queue.append(q)
    if reasons or problems:
        return EntryResult(entry.label, UNDETERMINED, reasons=tuple(dict.fromkeys(reasons)))
    return EntryResult(entry.label, NO_PATH)


def analyse(modules: list[tuple[str, str]], problems: list[str] | None = None) -> VbaChains:
    """modules: (module name, VBA source). `problems`: reasons found while extracting them."""
    result = VbaChains(problems=list(problems or []))
    procedures, shadowed, comment_free = [], set(), []
    for module, source in modules:
        procs, outside, names = parse(module, source, result.problems)
        procedures += procs
        shadowed |= names
        if found := strong(outside):
            result.problems.append(f"{module}: dangerous keywords outside any procedure ({'; '.join(found)})")
        whole = outside + "\n" + "\n".join(p.text for p in procs)
        comment_free.append((module, whole))
        located = set(strong("\n".join(p.text for p in procs)))
        if missing := sorted(set(strong(whole)) - located - set(found)):
            result.problems.append(f"{module}: olevba reports {'; '.join(missing)} but no procedure accounts for it")
    if len(procedures) > MAX_PROCEDURES:
        raise VbaChainError(f"VBA project has more than {MAX_PROCEDURES} procedures")

    by_name: dict[str, list[Procedure]] = {}
    for p in procedures:
        p.demonstrated, p.possible = capabilities(p.text, "\n".join(line for line, _ in p.code))
        by_name.setdefault(p.name.lower(), []).append(p)
    module_names = {m.lower(): m for m, _ in modules}
    for p in procedures:
        link(p, by_name, module_names, shadowed)

    entries = [p for p in procedures if p.name.lower() in _ENTRY_NAMES or any(r.match(p.name) for r in _ENTRY_PATTERNS)]
    defined = {p.name.lower() for p in entries}
    for module, code in comment_free:
        for kind, keyword, _ in VBA_Scanner(code).scan():
            if kind == "AutoExec" and keyword.lower() not in defined:
                result.problems.append(f"{module}: automatic-entry keyword {office.clean(keyword, 40)!r} "
                                       "is not a procedure this analysis found")
    result.entries = [search(entry, result.problems) for entry in entries]
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
