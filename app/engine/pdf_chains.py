"""PDF action chains: which trigger runs which actions, and which embedded files they use.

The custom engine's own analysis (FilesMagic capstone). Parsing is reused: pypdf, with the PDF
scanner's decompression limits, skipped keys, automatic-trigger set and string helpers
(app.scanners.pdf), so both see the same document. What is new is the model:

  chain   = one trigger + the actions it starts. Triggers (ISO 32000-1 12.6.3): the catalog's
            /OpenAction, an /AA entry of any dictionary (automatic if its key is one of
            AUTO_TRIGGERS), an /A entry (annotation or outline click), and each document-level
            script in the /JavaScript name tree (runs on open).
  actions = the trigger's action dictionary and its /Next actions (12.6.2), nothing else. A
            GoTo destination that leads to a page does not make that page's links part of the
            chain; that page's own /AA is a trigger of its own.
  payload = an embedded file named by the action: Launch /F with an embedded file stream,
            GoToE /T /N, or a JavaScript data-object call (exportDataObject, ...) whose
            cName is a literal or computed. A computed name counts as a link to every attachment.

The reference PDF scanner instead marks everything reachable from an automatic trigger as
automatic, and combines "automatic script" with "any attachment anywhere". Here an escalation
needs both on the same chain (rules in app.engine.correlate).

Bounds: objects visited (MAX_OBJECTS), nesting depth (MAX_DEPTH) and actions (MAX_ACTIONS);
exceeding one raises ChainScanError, as does any parser failure, so nothing is silently cut.
"""

import io
import logging
import re
from dataclasses import dataclass, field

from pypdf import PasswordType, PdfReader, apply_configuration
from pypdf.errors import PdfReadError
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

from app.scanners.base import ScanError
from app.scanners.pdf import (
    AUTO_TRIGGERS, MAX_DEPTH, MAX_JS_BYTES, MAX_OBJECTS, PDF_LIMITS, SKIP_KEYS, _RepairLog, clean, filespec_name,
    is_pdf, text_of,
)

MAX_ACTIONS = 10_000
COMPUTED = "<computed name>"  # a data-object call whose name is not a string literal
DATA_OBJECT_CALL = re.compile(r"\b(exportDataObject|openDataObject|getDataObjectContents|getDataObject)\s*\(")
# cName: "x" (object form) or the first argument (positional form) of a data-object call.
DATA_OBJECT_NAME = re.compile(
    r"""(?:\bcName\s*:\s*|\b(?:exportDataObject|openDataObject|getDataObjectContents|getDataObject)\s*\(\s*)"""
    r"""(["'])([^"'\\\r\n]{0,200})\1""")


class ChainScanError(ScanError):
    malformed_causes = (PdfReadError,)


@dataclass(frozen=True)
class Action:
    where: str  # "object 7 0", or "direct in <owner>"
    kind: str  # /S without the slash, or "JavaScript" for a dictionary that only has /JS
    payload: tuple[tuple[str, str], ...] = ()  # (embedded file name or COMPUTED, how: launch/export/open)
    target: str = ""  # Launch target that is not embedded, shown as evidence
    script: bool = False  # has /JS: JavaScript actions, and Rendition actions with a script (12.6.4.13)


@dataclass
class Chain:
    trigger: str  # e.g. "catalog /OpenAction", "object 3 0 /AA /O"
    automatic: bool
    actions: list[Action] = field(default_factory=list)


@dataclass
class PdfChains:
    chains: list[Chain] = field(default_factory=list)
    attachments: set[str] = field(default_factory=set)  # name-tree keys and file names of /EF file specs
    repaired: int = 0  # pypdf repair warnings: the structure is a best-effort reading

    def linked(self, chain: Chain) -> list[tuple[Action, str, str]]:
        """(action, attachment, how) for every payload of `chain` that names an attachment."""
        return [(a, name, how) for a in chain.actions for name, how in a.payload
                if name in self.attachments or (name == COMPUTED and self.attachments)]


def _resolve(value):
    return value.get_object() if isinstance(value, IndirectObject) else value


def _label(ref: IndirectObject) -> str:
    return f"object {ref.idnum} {ref.generation}"


def _describe(action: DictionaryObject, where: str) -> Action:
    kind = str(action.get("/S", "/JavaScript")).lstrip("/")
    payload, target = [], ""
    if "/JS" in action:
        script = text_of(action["/JS"], MAX_JS_BYTES)
        if DATA_OBJECT_CALL.search(script):
            names = [m.group(2) for m in DATA_OBJECT_NAME.finditer(script)]
            payload += [(n, "export") for n in names] or [(COMPUTED, "export")]
    if kind == "Launch":
        spec = _resolve(action.get("/F"))
        if spec is None and isinstance(win := _resolve(action.get("/Win")), DictionaryObject):
            spec = _resolve(win.get("/F"))  # Windows launch parameters (12.6.4.5)
        name = filespec_name(spec or "")
        if isinstance(spec, DictionaryObject) and "/EF" in spec:
            payload.append((name, "launch"))
        else:
            target = clean(name, 80)
    if kind == "GoToE":
        tree = _resolve(action.get("/T"))
        while isinstance(tree, DictionaryObject):  # target chain: /T entries nest, /N names the file
            if "/N" in tree:
                payload.append((text_of(tree["/N"], 1000), "open"))
            tree = _resolve(tree.get("/T"))
    return Action(where, kind, tuple(payload), target, "/JS" in action)


def _actions(value, owner: str, budget: list[int]) -> list[Action]:
    """The action dictionaries of one chain: `value` and its /Next actions, in order."""
    actions, seen, todo = [], set(), [(value, f"direct in {owner}")]
    while todo:
        value, where = todo.pop(0)
        if isinstance(value, IndirectObject):
            if (value.idnum, value.generation) in seen:
                continue  # /Next cycles are legal syntax; each action runs once here
            seen.add((value.idnum, value.generation))
            where, value = _label(value), value.get_object()
        if isinstance(value, ArrayObject):
            todo[:0] = [(v, where) for v in value]
            continue
        if not isinstance(value, DictionaryObject) or not ("/S" in value or "/JS" in value):
            continue  # a destination array or anything else: not an action
        budget[0] -= 1
        if budget[0] < 0:
            raise ChainScanError(f"PDF has more than {MAX_ACTIONS} actions")
        actions.append(_describe(value, where))
        if "/Next" in value:  # raw_get keeps the reference: value["/Next"] would resolve it past `seen`
            todo.insert(0, (value.raw_get("/Next"), f"direct in {where}"))
    return actions


def _name_tree(tree):
    """(key, value) pairs of a name tree (7.9.6): /Names arrays and /Kids, each node once."""
    seen, todo = set(), [(tree, 0)]
    while todo:
        node, depth = todo.pop()
        if isinstance(node, IndirectObject):
            if (node.idnum, node.generation) in seen:
                continue
            seen.add((node.idnum, node.generation))
        node = _resolve(node)
        if not isinstance(node, DictionaryObject):
            continue
        if depth > MAX_DEPTH or len(seen) > MAX_OBJECTS:
            raise ChainScanError("PDF name tree is nested too deeply or too large")
        names, kids = _resolve(node.get("/Names")), _resolve(node.get("/Kids"))
        if isinstance(names, ArrayObject):
            for i in range(0, len(names) - 1, 2):
                yield text_of(names[i], 1000), names[i + 1]
        if isinstance(kids, ArrayObject):
            todo.extend((kid, depth + 1) for kid in kids)


def extract(data: bytes) -> PdfChains:
    reader = PdfReader(io.BytesIO(data), strict=False)
    if reader.is_encrypted and reader.decrypt("") == PasswordType.NOT_DECRYPTED:
        raise ChainScanError("PDF is password-protected; its actions cannot be read")
    root = reader.trailer.get("/Root")
    if root is None:
        raise ChainScanError("PDF has no document catalog")

    result, budget = PdfChains(), [MAX_ACTIONS]

    def chain(trigger: str, automatic: bool, value, owner: str) -> None:
        if actions := _actions(value, owner, budget):
            result.chains.append(Chain(trigger, automatic, actions))

    seen, visited = set(), 0
    stack = [(root, 0, "catalog")]  # (object, depth, label of the indirect object it is in)
    while stack:
        obj, depth, owner = stack.pop()
        if isinstance(obj, IndirectObject):
            if (obj.idnum, obj.generation) in seen:
                continue
            seen.add((obj.idnum, obj.generation))
            owner = "catalog" if obj == root else _label(obj)
            obj, depth = obj.get_object(), 0
        if not isinstance(obj, (DictionaryObject, ArrayObject)):
            continue
        visited += 1
        if visited > MAX_OBJECTS:
            raise ChainScanError(f"PDF structure exceeds {MAX_OBJECTS} objects")
        if depth > MAX_DEPTH:
            raise ChainScanError(f"PDF structure is nested deeper than {MAX_DEPTH} levels")
        if isinstance(obj, ArrayObject):
            stack.extend((v, depth + 1, owner) for v in obj)
            continue

        if "/EF" in obj:
            result.attachments.add(filespec_name(obj))
        for k, v in obj.items():
            if k in SKIP_KEYS:
                continue
            if k == "/OpenAction":
                chain(f"{owner} /OpenAction", True, v, owner)
            elif k == "/AA" and isinstance(triggers := _resolve(v), DictionaryObject):
                for trigger, action in triggers.items():
                    chain(f"{owner} /AA {trigger}", trigger in AUTO_TRIGGERS, action, owner)
            elif k == "/A":
                chain(f"{owner} /A", False, v, owner)
            elif k == "/JavaScript" and not isinstance(v, str):  # the names dictionary's script tree
                # Not a name tree (a bare action or array): automatic too, as the PDF scanner treats it.
                for name, action in list(_name_tree(v)) or [("(not a name tree)", v)]:
                    chain(f"document-level script {clean(name, 40)!r}", True, action, owner)
            elif k == "/EmbeddedFiles" and not isinstance(v, str):
                result.attachments.update(name for name, _ in _name_tree(v))
            stack.append((v, depth + 1, owner))  # triggers too: their objects may hold file specs
    result.attachments.discard("")
    return result


def scan(data: bytes) -> PdfChains | None:
    """The chains of a PDF, None for any other file. Raises ChainScanError if unreadable."""
    if not is_pdf(data):
        return None
    log, pypdf_logger = _RepairLog(), logging.getLogger("pypdf")
    pypdf_logger.addHandler(log)
    try:
        with apply_configuration(**PDF_LIMITS):
            result = extract(data)
    except ChainScanError:
        raise
    except Exception as e:  # any parser failure, including RecursionError on hostile nesting
        raise ChainScanError(f"PDF action-chain analysis failed: {type(e).__name__}: {clean(e, 200)}") from e
    finally:
        pypdf_logger.removeHandler(log)
    result.repaired = log.count
    return result
