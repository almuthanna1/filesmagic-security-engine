"""VBA call graphs: is there a demonstrated path from an automatic procedure to a dangerous operation?

The custom engine's own analysis (FilesMagic capstone). Source comes from oletools' extractor
(app.engine.vba_analysis.extract: decompression only). Which procedures Office runs on its own
(entry points), and which operations a procedure performs (capabilities, each DEMONSTRATED or
only POSSIBLE, in context), are decided by app.engine.vba_analysis. New here: procedures, a call
graph whose edges are each either DEMONSTRATED or only POSSIBLE, and a search from every entry.

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
                dangerous operation outside any procedure or one only the whole module's text
                shows, an entry name used but never defined, XLM macros, or a VBA project that
                could not be read

"no-path" is a statement about the source only. Office may execute the compiled P-code instead,
and VBA stomping replaces the source while keeping malicious P-code; the isolated worker cannot
check that. So app.engine.correlate never lowers a finding on "no-path"; it only reports it.

Nothing is executed. Inputs are bounded by the Office scanner's limits and MAX_SOURCE_BYTES.
"""

import functools
import io
import re
import zipfile
from collections import deque
from dataclasses import dataclass, field

from app.engine import vba_analysis as va
from app.scanners import office
from app.scanners.base import ScanError

LINKED, NO_PATH, UNDETERMINED = "linked", "no-path", "undetermined"
DEMONSTRATED, POSSIBLE = "demonstrated", "possible"
MAX_SOURCE_BYTES = va.MAX_SOURCE_BYTES  # all modules of a document together
MAX_PROCEDURES = 20_000

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


class VbaChainError(ScanError):
    malformed_causes = office.OfficeScanError.malformed_causes


@dataclass
class Procedure:
    module: str
    name: str
    params: str = ""  # the parameter list of its declaration line
    source: list[tuple[int, str]] = field(default_factory=list)  # (line number, logical line), for analysis
    code: list[tuple[str, list[str]]] = field(default_factory=list)  # (line, strings blanked; its literals)
    demonstrated: list[str] = field(default_factory=list)  # capability descriptions with their keywords
    possible: list[str] = field(default_factory=list)
    edges: list[tuple["Procedure", str, str]] = field(default_factory=list)  # (callee, kind, why)
    dynamic: list[str] = field(default_factory=list)
    declare: bool = False  # a Declare statement: an external function, never an entry

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
    trigger: str = ""  # how Office starts it (vba_analysis.entry_trigger)


@dataclass
class VbaChains:
    entries: list[EntryResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # project-wide reasons for undetermined
    # Raw extracted modules for bounded INFO evidence; never execute them.
    sources: list[tuple[str, str]] = field(default_factory=list)
    # Project-wide results the Office scanner reports, each with the procedure it was found in.
    capabilities: list[tuple[str, va.Capability]] = field(default_factory=list)
    decoded: list[tuple[str, va.Decoded]] = field(default_factory=list)

    @property
    def outcome(self) -> str:
        outcomes = {e.outcome for e in self.entries}
        return LINKED if LINKED in outcomes else UNDETERMINED if UNDETERMINED in outcomes or self.problems else NO_PATH


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


def parse(module: str, source: str, problems: list[str]) -> tuple[list[Procedure], list[tuple[int, str]], set[str]]:
    """Procedures of one module, its logical lines outside them, and the names those lines declare."""
    procedures, outside, module_names, current, in_enum = [], [], set(), None, False
    for number, raw in va.logical_lines(source):
        line, literals, _ = _clean(raw)
        if declared_function := _DECLARE.match(line):
            procedures.append(Procedure(module, declared_function.group(1), "", [(number, raw)], [(line, literals)],
                                        declare=True))
            continue
        if start := _START.match(line):
            if current:
                problems.append(f"{module}: {current.name} has no End before {start.group(1)} starts")
                procedures.append(current)
            current = Procedure(module, start.group(1), start.group(2) or "")
        if current:
            current.source.append((number, raw))
            current.code.append((line, literals))
            if _END.match(line):
                procedures.append(current)
                current = None
            continue
        outside.append((number, raw))
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
    return procedures, outside, module_names


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


def _strong(analysis: va.CodeAnalysis) -> list[va.Capability]:
    return [c for c in analysis.capabilities if c.strong]


def analyse(modules: list[tuple[str, str]], problems: list[str] | None = None) -> VbaChains:
    """modules: (module name, VBA source). `problems`: reasons found while extracting them."""
    result = VbaChains(problems=list(problems or []), sources=list(modules))
    parsed, procedures, shadowed = [], [], set()
    for module, source in modules:
        procs, outside, names = parse(module, source, result.problems)
        parsed.append((module, procs, outside))
        procedures += procs
        shadowed |= names
    if len(procedures) > MAX_PROCEDURES:
        raise VbaChainError(f"VBA project has more than {MAX_PROCEDURES} procedures")
    ctx = va.context([(m, va.logical_lines(src)) for m, src in modules],
                     {p.name.lower() for p in procedures if not p.declare})

    by_name: dict[str, list[Procedure]] = {}
    for p in procedures:
        analysis = va.analyse_code(p.source, ctx, _first_names(p.params))
        p.demonstrated = [c.text() for c in _strong(analysis) if c.status == va.DEMONSTRATED]
        p.possible = [c.text() for c in _strong(analysis) if c.status == va.POSSIBLE]
        result.capabilities += [(p.label, c) for c in analysis.capabilities]
        result.decoded += [(p.label, d) for d in analysis.decoded]
        by_name.setdefault(p.name.lower(), []).append(p)

    for module, procs, outside in parsed:
        # Executable code outside a procedure is not valid VBA: never ignore what it could do.
        outer = va.analyse_code(outside, ctx)
        result.capabilities += [(f"{module} (outside any procedure)", c) for c in outer.capabilities]
        result.decoded += [(f"{module} (outside any procedure)", d) for d in outer.decoded]
        if found := _strong(outer):
            result.problems.append(f"{module}: dangerous operations outside any procedure "
                                   f"({'; '.join(c.text() for c in found[:3])})")
        # Read as one block, the module may show what no single procedure does (an object created in
        # one procedure and used in another): that is a path this graph cannot attribute.
        whole = va.analyse_code(sorted(outside + [line for p in procs for line in p.source]), ctx)
        labels = {p.label for p in procs}
        located = {(c.kind, c.status) for label, c in result.capabilities if label in labels}
        if missing := sorted({c.text() for c in _strong(whole) if c.status == va.DEMONSTRATED
                              and (c.kind, va.DEMONSTRATED) not in located}):
            result.problems.append(f"{module}: the module's code as a whole shows {'; '.join(missing[:3])}, "
                                   "which no single procedure does")

    module_names = {m.lower(): m for m, _ in modules}
    for p in procedures:
        link(p, by_name, module_names, shadowed)

    entries = [p for p in procedures if not p.declare and va.entry_trigger(p.name)]
    defined = {p.name.lower() for p in entries}
    for module, procs, outside in parsed:
        mentioned = {}  # lower-case name -> as written (identifiers and string literals)
        for _, text in outside + [line for p in procs for line in p.source]:
            for t in va.tokenize(text):
                if t.kind in ("id", "str"):
                    mentioned.setdefault(str(t.value).lower(), t.text.strip('"[]'))
        for name in sorted((mentioned.keys() & va.ENTRY_NAMES) - defined):
            result.problems.append(f"{module}: automatic-entry keyword {office.clean(mentioned[name], 40)!r} "
                                   "is not a procedure this analysis found")
    result.entries = [EntryResult(**{**vars(search(entry, result.problems)), "trigger": va.entry_trigger(entry.name)})
                      for entry in entries]
    return result


@functools.lru_cache(maxsize=4)
def analyse_cached(modules: tuple[tuple[str, str], ...], problems: tuple[str, ...] = ()) -> VbaChains:
    """analyse() once per project and worker: the Office scanner and this scanner share it."""
    return analyse(list(modules), list(problems))


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
        extracted = va.extract(blob, label)
        if extracted.error is not None:
            problems.append(f"{office.clean(label, 60)} could not be extracted ({type(extracted.error).__name__})")
            continue
        if extracted.xlm:
            problems.append("Excel 4.0 (XLM) macros are present; they are not part of this call graph")
        total += sum(len(code) for _, code in extracted.modules)
        if extracted.too_large or total > MAX_SOURCE_BYTES:
            raise VbaChainError(f"VBA source exceeds {MAX_SOURCE_BYTES} bytes")
        modules += [m for m in extracted.modules if m[0] != va.XLM_MODULE]
    return analyse_cached(tuple(modules), tuple(problems)) if modules or problems else None
