"""OOXML activation graph: which relationships and embedded objects the document actually uses.

The custom engine's own analysis (FilesMagic capstone). Reused: the custom detector's OPC reader
(app.scanners.custom.ooxml_package: content types, every relationship resolved to part keys,
bounded part reads, fail-closed on broken essential parts), its relationship namespaces and XML
test (app.scanners.custom.ooxml), and defusedxml. New here: which parts Office loads, which element
references each relationship, and what that element says about when the target is used.

A relationship (ECMA-376 Part 2, 9.3) is an Id-labelled, typed arrow from a source part to a
target part or, with TargetMode="External", to something outside the file. It is used only when
Office loads the source part and an element in that part references its Id (an r:* attribute,
or VML's o:relid). The element says when (ISO/IEC 29500-1 element semantics, Microsoft Learn
Open XML reference): w:attachedTemplate "shall be attached" (settings part); a:blip r:link names
"an image that does not reside within this file"; o:OLEObject Type="Link" with UpdateMode, the
Excel oleObject oleUpdate attribute and PowerPoint's p:link updateAutomatic say whether a linked
object is refreshed automatically. Office's runtime behaviour itself is not observed here.

Activation of each relationship of interest (external ones, and internal ones to OLE objects,
embedded packages and ActiveX controls):
  on-open        an external target the document asks for when it opens (template, frame, OLE
                 link that updates automatically); whether it is fetched depends on the
                 application's external-content and Protected View settings
  linked-picture an external picture shown in the document, fetched only if the application
                 loads external content
  on-action      an external target used when the user updates or expands it (OLE link on
                 request, subdocument)
  click          a hyperlink (not reported)
  displayed      an embedded object or control referenced by an element (it runs only when
                 activated; ActiveX controls are created when the document opens, after a prompt)
  not-activated  the source part is never loaded, or no element in it references the Id
  undetermined   the source part could not be read, is binary or malformed, the Id is declared
                 twice, or the referencing element is not one this analysis models
"""

import io
import zipfile
from collections import deque
from dataclasses import dataclass, field

import defusedxml.ElementTree as SafeET

from app.scanners import office
from app.scanners.custom import ooxml_package as opc
from app.scanners.custom.ooxml import REL_NAMESPACES, is_xml

ON_OPEN, IMAGE, ON_ACTION, CLICK, DISPLAYED = "on-open", "linked-picture", "on-action", "click", "displayed"
NOT_ACTIVATED, UNDETERMINED = "not-activated", "undetermined"
EMBED_TYPES = {"oleobject", "package", "control"}  # internal relationship types to objects
_REL_NS = {ns.decode() for ns in REL_NAMESPACES}
_VML_OFFICE = "urn:schemas-microsoft-com:office:office"
_STRENGTH = [ON_OPEN, IMAGE, UNDETERMINED, ON_ACTION, CLICK, DISPLAYED]


@dataclass
class Reference:
    element: str  # local name of the element carrying the Id
    attribute: str  # local name of the attribute
    attrs: dict[str, str]  # its attributes by local name
    auto_update: bool = False  # PowerPoint: a child p:link with updateAutomatic="1"


@dataclass(frozen=True)
class Activation:
    relationship: opc.Relationship
    state: str
    why: str
    chain: str  # how Office reaches the source part, and the referencing element


@dataclass(frozen=True)
class ReferenceTarget:
    rels_part: str  # lower case, as the Office scanner keys members
    id: str
    type: str  # last segment of the relationship type, as written
    target: str


@dataclass
class Links:
    activations: list[Activation] = field(default_factory=list)
    unrelated_objects: list[str] = field(default_factory=list)  # object parts no relationship leads to
    # Office-scanner rule -> every external relationship behind it; None: not established, so no
    # reference finding about relationships may be superseded or merged.
    reference: dict[str, list[ReferenceTarget]] | None = None

    def activation(self, t: ReferenceTarget) -> Activation | None:
        found = [a for a in self.activations
                 if a.relationship.rels_part.lower() == t.rels_part and a.relationship.id == t.id]
        return found[0] if len(found) == 1 else None


def reference_targets(data: bytes) -> dict[str, list[ReferenceTarget]] | None:
    """The external relationships behind each Office-scanner finding, listed exactly as
    app.scanners.office.scan_ooxml lists them: the same members, XML reader and classifier
    (external_relationship), so the two analyses talk about the same relationships. None when the
    package can be read in more than one way (duplicate, encrypted or unsafe member names), when the
    Office scanner would stop at its size limits, or when anything here fails."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if (len(infos) > office.MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > office.MAX_TOTAL_UNCOMPRESSED
                    or len({i.filename.lower() for i in infos}) != len(infos)
                    or any(i.flag_bits & 0x1 or office.unsafe_member_name(i.filename) for i in infos)):
                return None
            found: dict[str, list[ReferenceTarget]] = {}
            for info in infos:
                if not info.filename.lower().endswith(".rels"):
                    continue
                for el in office.iter_xml(zf, info):
                    if office.local(el.tag) != "Relationship" or el.get("TargetMode", "").lower() != "external":
                        continue
                    rel_type, target = el.get("Type", "").rsplit("/", 1)[-1], el.get("Target", "")
                    if verdict := office.external_relationship(rel_type, target):
                        found.setdefault(verdict[2], []).append(
                            ReferenceTarget(info.filename.lower(), el.get("Id", ""), rel_type, target))
            return found
    except Exception:  # ponytail: any doubt means "not established"; the Office scanner reports its own failure
        return None


def _local(name: str) -> tuple[str, str]:
    ns, _, local = name[1:].partition("}") if name.startswith("{") else ("", "", name)
    return ns, local


def references(data: bytes) -> dict[str, list[Reference]]:
    """Relationship Id -> the elements of an XML part that reference it. Raises the XML parser's
    errors (opc.MALFORMED) on malformed input."""
    found: dict[str, list[Reference]] = {}
    stack: list[Reference | None] = []
    for event, el in SafeET.iterparse(io.BytesIO(data), events=("start", "end"), forbid_dtd=True):
        _, tag = _local(el.tag)
        if event == "start":
            attrs = {_local(k)[1]: v for k, v in el.attrib.items()}
            ref = None
            for k, v in el.attrib.items():
                ns, name = _local(k)
                if ns in _REL_NS or (ns == _VML_OFFICE and name == "relid"):
                    ref = Reference(tag, name, attrs)
                    found.setdefault(v.strip(), []).append(ref)
            if tag == "link" and attrs.get("updateAutomatic") in ("1", "true"):
                owner = next((r for r in reversed(stack) if r and r.element == "oleObj"), None)
                if owner:
                    owner.auto_update = True
            stack.append(ref)
        else:
            stack.pop()
            el.clear()
    return found


def classify(ref: Reference, external: bool) -> tuple[str, str]:
    """(activation, why) of one referencing element."""
    a, element = ref.attrs, ref.element
    if not external:
        if element in ("OLEObject", "oleObj", "oleObject", "control", "ocx", "objectEmbed"):
            return DISPLAYED, f"{element} shows it in the document"
        return UNDETERMINED, f"referenced by {element}, which this analysis does not model"
    if element == "attachedTemplate":
        return ON_OPEN, "w:attachedTemplate: the template is attached when the document opens"
    if element == "sourceFileName":
        return ON_OPEN, "frame source: loaded when the document opens"
    if element in ("blip", "imagedata"):
        return IMAGE, f"{element} {ref.attribute}: a picture stored outside the file"
    linked_ole = (element == "OLEObject" and a.get("Type", "").lower() == "link") or element in ("oleObj", "oleObject")
    if linked_ole:
        always = (a.get("UpdateMode", "").lower() == "always" or a.get("oleUpdate") == "OLEUPDATE_ALWAYS"
                  or ref.auto_update)
        return (ON_OPEN, f"linked {element} that updates automatically") if always else \
            (ON_ACTION, f"linked {element} updated on request")
    if element == "subDoc":
        return ON_ACTION, "subdocument: loaded when the master document is expanded"
    if element in ("hyperlink", "hlinkClick", "hlinkHover"):
        return CLICK, "hyperlink"
    return UNDETERMINED, f"referenced by {element}, which this analysis does not model"


def loaded_parts(package: opc.Package) -> dict[str, tuple[str, str]]:
    """Every part Office reaches from the package relationships: part -> (parent part, rel type)."""
    by_source: dict[str, list[opc.Relationship]] = {}
    for r in package.relationships:
        by_source.setdefault(r.source, []).append(r)
    parent, queue = {"": ("", "")}, deque([""])
    while queue:
        source = queue.popleft()
        for r in by_source.get(source, ()):
            if not r.external and r.resolved in package.parts and r.resolved not in parent:
                parent[r.resolved] = (source, r.type.rsplit("/", 1)[-1])
                queue.append(r.resolved)
    return parent


def _chain(package: opc.Package, parent: dict, part: str) -> str:
    steps = []
    while part:
        up, rel_type = parent[part]
        steps.append(f"{package.name(part)} ({rel_type})")
        part = up
    return " -> ".join(["package", *reversed(steps)])


def analyse(package: opc.Package) -> Links:
    parent = loaded_parts(package)
    interesting = [r for r in package.relationships
                   if r.external or r.type.rsplit("/", 1)[-1] in EMBED_TYPES]
    result, read = Links(), {}
    for r in interesting:
        how = r.type.rsplit("/", 1)[-1]
        target = r.target if r.external else package.name(r.resolved or r.target)
        where = package.name(r.source) if r.source else "the package"
        if r.source and r.source not in parent:
            result.activations.append(Activation(r, NOT_ACTIVATED, f"{where} is never loaded: no relationship leads "
                                                 "to it", where))
            continue
        if r.source not in read:
            read[r.source] = _read_references(package, r.source)
        refs = read[r.source]
        chain = _chain(package, parent, r.source)
        if isinstance(refs, str):
            result.activations.append(Activation(r, UNDETERMINED, refs, chain))
            continue
        if sum(x.id == r.id for x in package.relationships if x.rels_part == r.rels_part) > 1:
            result.activations.append(Activation(r, UNDETERMINED, f"Id {r.id!r} is declared more than once", chain))
            continue
        found = refs.get(r.id, [])
        if not found:
            result.activations.append(Activation(r, NOT_ACTIVATED, f"no element in {where} references {r.id!r}",
                                                 chain))
            continue
        state, why = min((classify(ref, r.external) for ref in found), key=lambda s: _STRENGTH.index(s[0]))
        element = next(ref for ref in found if classify(ref, r.external)[0] == state)
        result.activations.append(Activation(r, state, why, f"{chain} -> {element.element} {element.attribute}="
                                             f"{r.id!r} -> {how} {target}"))
    related = {r.resolved for r in package.relationships if not r.external}
    result.unrelated_objects = [package.name(p) for p in package.parts
                                if ("/embeddings/" in p or "/activex/" in p) and p not in related]
    return result


def _read_references(package: opc.Package, source: str) -> dict[str, list[Reference]] | str:
    """The references in a source part, or why they cannot be known."""
    if not source:
        return {}  # the package itself has no XML that could reference an Id
    if not is_xml(package, source):
        return f"{package.name(source)} is not XML, so its references cannot be read"
    data = package.read(source, opc.MAX_PART_BYTES, required=False)
    if data is None:
        return f"{package.name(source)} could not be read"
    try:
        return references(data)
    except opc.MALFORMED:
        return f"{package.name(source)} is not well-formed XML"


def scan(data: bytes) -> Links | None:
    """None if this is not an OPC package. Raises CustomScanError (fail closed) when its
    content types or relationship parts cannot be read."""
    package = opc.open_package(data)
    if package is None:
        return None
    result = analyse(package)
    result.reference = reference_targets(data)
    return result
