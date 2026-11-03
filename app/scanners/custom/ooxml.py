"""C4-C6: OOXML declaration, relationship-graph and container indicators.

Three independent methods over one parsed package (app.scanners.custom.ooxml_package). Each
rule has a fixed, conservative severity; nothing is added up or escalated. Normal macro-enabled
documents, high compression and leftover parts are INFO: on their own they are common in benign
files. LOW marks a structure that standard Office generators do not produce; MEDIUM is used once,
for a package whose declared type contradicts the macro code it carries.

C4 declaration consistency (category office-declaration)
  CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH   MEDIUM  macro-free main type, macro parts present
  CUSTOM_OFFICE_FAMILY_MISMATCH              LOW     main part type and location (word/, xl/,
                                                     ppt/) disagree, or several families' main
                                                     document types are declared
  CUSTOM_OFFICE_AMBIGUOUS_MAIN_DOCUMENT      LOW     several officeDocument relationships
  CUSTOM_OFFICE_UNDECLARED_PARTS             LOW     parts with no content type, or conflicting
                                                     declarations for one part or extension
  CUSTOM_OFFICE_MACRO_CAPABLE_DECLARATION    INFO    declared macro-enabled (normal for .docm etc.)
  CUSTOM_OFFICE_UNCONVENTIONAL_MAIN_PART     INFO    valid main type outside its usual directory
  CUSTOM_OFFICE_STALE_DECLARATIONS           INFO    Override for a part that does not exist
C5 relationship graph (category office-relationships)
  CUSTOM_OFFICE_REL_DUPLICATE_ID             LOW     one Id declared twice in a relationship part
  CUSTOM_OFFICE_CONCEALED_BINARY_PART        LOW     binary part no relationship leads to
  CUSTOM_OFFICE_UNREACHABLE_PARTS            INFO    other parts no relationship leads to
  CUSTOM_OFFICE_REL_MISSING_TARGET           INFO    internal relationship to a missing part
  CUSTOM_OFFICE_REL_DANGLING_REFERENCE       INFO    r:id-style reference with no relationship
C6 ZIP container (category office-container): metadata only, nothing is decompressed
  CUSTOM_OFFICE_ZIP_IMPOSSIBLE_SIZE          LOW     declared sizes no real entry can have
  CUSTOM_OFFICE_ZIP_HEADER_MISMATCH          LOW     local header contradicts the central directory
  CUSTOM_OFFICE_ZIP_OVERLAPPING_ENTRIES      LOW     entries share compressed data
  CUSTOM_OFFICE_ZIP_UNSUPPORTED_METHOD       LOW     compression Office cannot read
  CUSTOM_OFFICE_ZIP_HIGH_RATIO               INFO    a large part with a very high ratio
  CUSTOM_OFFICE_ZIP_OVERSIZED_PART           INFO    a part above this detector's read limit
Coverage
  CUSTOM_OFFICE_COVERAGE_LIMITED             INFO    what could not be analysed, and why

C4 and C5 apply to Word, Excel and PowerPoint packages. Other OPC packages (XPS, Visio, NuGet,
MSIX, ...) get only the container checks, and say so in a coverage finding.
"""

import re
import struct
from collections import Counter, defaultdict
from xml.sax.saxutils import unescape

from app.models import Severity
from app.scanners.custom import ooxml_package as opc
from app.scanners.custom.indicators import Signal, clean
from app.scanners.custom.ooxml_package import (
    CONTENT_TYPES, PACKAGE_RELS, READABLE_METHODS, MainDocument, Package, main_document, rels_part_for,
)

# Main document content types (ECMA-376 Part 1 and [MS-OFFCRYPTO]-era Office extensions):
# content type -> (family, kind, macro-enabled).
MAIN_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": ("Word", "document", False),
    "application/vnd.ms-word.document.macroenabled.main+xml": ("Word", "document", True),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": ("Word", "template", False),
    "application/vnd.ms-word.template.macroenabledtemplate.main+xml": ("Word", "template", True),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": ("Excel", "workbook", False),
    "application/vnd.ms-excel.sheet.macroenabled.main+xml": ("Excel", "workbook", True),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": ("Excel", "template", False),
    "application/vnd.ms-excel.template.macroenabled.main+xml": ("Excel", "template", True),
    "application/vnd.ms-excel.addin.macroenabled.main+xml": ("Excel", "add-in", True),
    "application/vnd.ms-excel.sheet.binary.macroenabled.main": ("Excel", "binary workbook", True),
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": ("PowerPoint", "presentation", False),
    "application/vnd.ms-powerpoint.presentation.macroenabled.main+xml": ("PowerPoint", "presentation", True),
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": ("PowerPoint", "slide show", False),
    "application/vnd.ms-powerpoint.slideshow.macroenabled.main+xml": ("PowerPoint", "slide show", True),
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": ("PowerPoint", "template", False),
    "application/vnd.ms-powerpoint.template.macroenabled.main+xml": ("PowerPoint", "template", True),
    "application/vnd.ms-powerpoint.addin.macroenabled.main+xml": ("PowerPoint", "add-in", True),
}
FAMILY_DIRS = {"word": "Word", "xl": "Excel", "ppt": "PowerPoint"}
MACRO_CONTENT_TYPES = {
    "application/vnd.ms-office.vbaproject", "application/vnd.ms-word.vbadata+xml",
    "application/vnd.ms-excel.macrosheet+xml", "application/vnd.ms-excel.intlmacrosheet+xml",
    "application/vnd.ms-excel.macrosheet",
}
VBA_RELATIONSHIP = "http://schemas.microsoft.com/office/2006/relationships/vbaproject"
TRASH = "[trash]/"  # Office 2007 left deleted parts here, unreferenced
TEXT_OR_IMAGE_EXTENSIONS = {"xml", "rels", "vml", "png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "emf", "wmf", "svg"}

# r:id, r:embed, r:link, ...: every attribute in this namespace names a relationship (ST_RelationshipId).
REL_NAMESPACES = {b"http://schemas.openxmlformats.org/officeDocument/2006/relationships",
                  b"http://purl.oclc.org/ooxml/officeDocument/relationships"}
_XMLNS = re.compile(rb"""xmlns:([A-Za-z_][\w.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')""")

DEFLATE_MAX_RATIO = 1032  # 258 bytes per 2-bit length/distance code is DEFLATE's ceiling
HIGH_RATIO, HIGH_RATIO_MIN_BYTES = 200, 1024 * 1024
LOCAL_HEADER = struct.Struct("<IHHHHHIIIHH")
LOCAL_SIGNATURE, DATA_DESCRIPTOR, UTF8_NAME, ZIP64_MARK = 0x04034B50, 0x08, 0x800, 0xFFFFFFFF


def q(name: str) -> str:
    return repr(clean(name, 60))


def describe(family: str, kind: str, macro: bool) -> str:
    return f"{'macro-enabled ' if macro else ''}{family} {kind}"


def _family_by_path(part: str | None) -> str | None:
    return FAMILY_DIRS.get(part.split("/", 1)[0]) if part and "/" in part else None


def office_family(main: MainDocument) -> tuple[tuple | None, str | None]:
    """(declared main type info or None, family implied by the main part's directory or None).
    The directory is taken from the relationship target even when that part is missing."""
    target = main.part or (main.relationships[0].resolved if main.relationships else None)
    return MAIN_TYPES.get(main.content_type or ""), _family_by_path(target)


# ----------------------------------------------------------------------------- C4


def macro_evidence(package: Package) -> tuple[list[str], list[str]]:
    """(macro parts, vbaProject relationships): by declared content type, by the names Office
    uses for them (vbaProject.bin, xl/macrosheets/), and by relationship type."""
    parts = [package.name(p) for p in package.parts
             if package.content_type(p) in MACRO_CONTENT_TYPES or p.rsplit("/", 1)[-1] == "vbaproject.bin"
             or p.startswith("xl/macrosheets/")]
    rels = [f"relationship {q(r.id)} of type vbaProject in {q(r.rels_part)}" for r in package.relationships
            if r.type == VBA_RELATIONSHIP]
    return parts, rels


def declaration(package: Package, main: MainDocument) -> list[Signal]:
    declared, by_path = office_family(main)
    where = ("[Content_Types].xml", PACKAGE_RELS)
    signals = []

    if len(main.relationships) > 1:
        signals.append(Signal(
            "CUSTOM_OFFICE_AMBIGUOUS_MAIN_DOCUMENT", "office-declaration", Severity.LOW,
            f"The package declares {len(main.relationships)} main documents; applications may open different ones.",
            tuple(f"{r.id!r} -> {q(r.target)}" for r in main.relationships), (PACKAGE_RELS,)))

    family = declared[0] if declared else by_path
    mismatch = []
    if main.part and not declared and by_path:
        mismatch.append(f"main part {q(package.name(main.part))} is declared as {q(main.content_type or 'nothing')}, "
                        f"not as a {by_path} main document")
    elif declared and by_path and declared[0] != by_path:
        mismatch.append(f"{declared[0]} main document type declared for {q(package.name(main.part))} "
                        f"in the {by_path} directory")
    for part, content_type in package.overrides.items():
        other = MAIN_TYPES.get(content_type)
        if other and other[0] != family and part != main.part:
            mismatch.append(f"also declares {q(part)} as a {other[0]} main document")
    if mismatch:
        signals.append(Signal(
            "CUSTOM_OFFICE_FAMILY_MISMATCH", "office-declaration", Severity.LOW,
            "The package's declared document type contradicts its structure, which can mislead tools that "
            "classify Office files by their part names.", tuple(mismatch), where))
    elif declared and not by_path and main.part:
        signals.append(Signal(
            "CUSTOM_OFFICE_UNCONVENTIONAL_MAIN_PART", "office-declaration", Severity.INFO,
            f"The {declared[0]} main document is stored outside the usual directory.",
            (f"main part {q(package.name(main.part))}",), where))

    if main.relationships and not main.part:
        package.coverage.append("the main document part is missing, so declaration checks were not applied")
    macro_parts, macro_rels = macro_evidence(package)
    if declared and not declared[2] and (macro_parts or macro_rels):
        signals.append(Signal(
            "CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH", "office-declaration", Severity.MEDIUM,
            f"The package is declared as a macro-free {declared[0]} {declared[1]} but contains macro code or "
            "macro sheets, so its declared type misrepresents what it carries.",
            (f"declared main type {q(main.content_type)}", *(f"macro part {q(m)}" for m in macro_parts), *macro_rels),
            where))
    elif declared and declared[2]:
        signals.append(Signal(
            "CUSTOM_OFFICE_MACRO_CAPABLE_DECLARATION", "office-declaration", Severity.INFO,
            f"The package is declared as a {describe(*declared)}, which is allowed to contain macros.",
            (f"declared main type {q(main.content_type)}", f"{len(macro_parts)} macro part(s) present"), where))

    undeclared = [package.name(p) for p in package.parts
                  if p != CONTENT_TYPES and not p.startswith(TRASH) and package.content_type(p) is None]
    if undeclared or package.declaration_conflicts:
        signals.append(Signal(
            "CUSTOM_OFFICE_UNDECLARED_PARTS", "office-declaration", Severity.LOW,
            "Parts have no content type, or conflicting ones; Office treats such packages as damaged and other "
            "readers may interpret them differently.",
            tuple([f"no content type: {q(n)}" for n in undeclared]
                  + [f"conflicting declarations for {clean(c, 120)}" for c in package.declaration_conflicts]),
            ("[Content_Types].xml",)))
    stale = [p for p in package.overrides if p not in package.parts]
    if stale:
        signals.append(Signal(
            "CUSTOM_OFFICE_STALE_DECLARATIONS", "office-declaration", Severity.INFO,
            "Content types are declared for parts that are not in the package.",
            tuple(f"Override for missing part {q(p)}" for p in stale), ("[Content_Types].xml",)))
    return signals


# ----------------------------------------------------------------------------- C5


def reachable(package: Package, by_source: dict) -> set[str]:
    """Parts reachable from the package relationships through internal relationships, plus the
    relationship parts of reachable sources."""
    seen, queue = {""}, [""]
    while queue:
        for r in by_source.get(queue.pop(), ()):
            if r.resolved in package.parts and r.resolved not in seen:
                seen.add(r.resolved)
                queue.append(r.resolved)
    return {p for p in seen if p} | {rels_part_for(s) for s in seen}


def is_binary(package: Package, part: str) -> bool:
    content_type = package.content_type(part)
    if content_type:
        return not (content_type.endswith("xml") or content_type.startswith("image/"))
    return part.rsplit(".", 1)[-1] not in TEXT_OR_IMAGE_EXTENSIONS


def is_xml(package: Package, part: str) -> bool:
    content_type = package.content_type(part) or ""
    return content_type.endswith("xml") or (not content_type and part.endswith(".xml"))


def references(data: bytes) -> set[str]:
    """Relationship Ids referenced by attributes in the relationships namespace, whatever its prefix."""
    prefixes = {m.group(1) for m in _XMLNS.finditer(data) if (m.group(2) or m.group(3) or b"") in REL_NAMESPACES} \
        if b"xmlns:" in data else set()
    ids = set()
    for prefix in prefixes:
        attribute = re.compile(rb"(?<![\w.:-])" + re.escape(prefix) + rb":[\w.-]+\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")
        for m in attribute.finditer(data):
            value = unescape((m.group(1) or m.group(2) or b"").decode("utf-8", "replace"), {"&quot;": '"', "&apos;": "'"})
            if value.strip():
                ids.add(value.strip())
    return ids


def relationships(package: Package) -> list[Signal]:
    by_source = defaultdict(list)
    for r in package.relationships:
        by_source[r.source].append(r)
    signals = []

    duplicates = [(part, rid, n) for part, ids in
                  ((rels, Counter(r.id for r in package.relationships if r.rels_part == rels))
                   for rels in dict.fromkeys(r.rels_part for r in package.relationships))
                  for rid, n in ids.items() if n > 1]
    if duplicates:
        signals.append(Signal(
            "CUSTOM_OFFICE_REL_DUPLICATE_ID", "office-relationships", Severity.LOW,
            "A relationship Id is declared more than once, so readers may resolve the same reference to "
            "different targets.", tuple(f"Id {q(rid)} declared {n} times" for _, rid, n in duplicates),
            tuple(dict.fromkeys(part for part, _, _ in duplicates))))

    live = reachable(package, by_source)
    unreachable = [p for p in package.parts if p not in live and p != CONTENT_TYPES]
    concealed = [p for p in unreachable if not p.startswith(TRASH) and is_binary(package, p)]
    leftovers = [p for p in unreachable if p not in concealed]
    if concealed:
        signals.append(Signal(
            "CUSTOM_OFFICE_CONCEALED_BINARY_PART", "office-relationships", Severity.LOW,
            f"{len(concealed)} binary part(s) are stored in the package but no relationship leads to them, so "
            "Office never loads them; such parts can carry data for other code to extract.",
            tuple(f"{q(package.name(p))} ({package.content_type(p) or 'no content type'}, "
                  f"{package.parts[p].file_size} bytes)" for p in concealed),
            tuple(package.name(p) for p in concealed)))
    if leftovers:
        signals.append(Signal(
            "CUSTOM_OFFICE_UNREACHABLE_PARTS", "office-relationships", Severity.INFO,
            f"{len(leftovers)} part(s) are not reachable through any relationship (often leftovers of editing).",
            tuple(q(package.name(p)) + (" (Office 2007 trash)" if p.startswith(TRASH) else "") for p in leftovers),
            tuple(package.name(p) for p in leftovers)))

    missing = [r for r in package.relationships if not r.external and r.resolved not in package.parts]
    if missing:
        signals.append(Signal(
            "CUSTOM_OFFICE_REL_MISSING_TARGET", "office-relationships", Severity.INFO,
            f"{len(missing)} internal relationship(s) point to parts that are not in the package.",
            tuple(f"{q(r.id)} -> {q(r.target)}" + ("" if r.resolved else " (not a part name in the package)")
                  for r in missing),
            tuple(dict.fromkeys(r.rels_part for r in missing))))

    unchecked = [p for p in live if p in package.parts and by_source.get(p) and not is_xml(package, p)]
    if unchecked:
        package.coverage.append(f"{len(unchecked)} binary part(s) with relationships (e.g. "
                                f"{q(package.name(unchecked[0]))}) not checked for dangling references")
    dangling = []
    for part in sorted(p for p in live if p in package.parts and is_xml(package, p) and p not in package.rels_sources):
        data = package.read(part, opc.MAX_PART_BYTES, required=False)
        if data is None:
            continue
        unknown = references(data) - {r.id for r in by_source.get(part, ())}
        if unknown:
            dangling.append((package.name(part), sorted(unknown)))
    if dangling:
        signals.append(Signal(
            "CUSTOM_OFFICE_REL_DANGLING_REFERENCE", "office-relationships", Severity.INFO,
            "Parts reference relationship Ids that their relationship part does not declare.",
            tuple(f"{q(name)} references {', '.join(q(i) for i in ids[:4])}" + (" ..." if len(ids) > 4 else "")
                  for name, ids in dangling),
            tuple(name for name, _ in dangling)))
    return signals


# ----------------------------------------------------------------------------- C6


def _local_header(package: Package, info) -> tuple[list[str], int | None]:
    """Differences between an entry's local file header and its central directory record, and
    where its data ends (None if there is no valid local header)."""
    offset, data = info.header_offset, package.data
    if offset + LOCAL_HEADER.size > len(data):
        return ["no local file header inside the file"], None
    sig, _, flags, method, _, _, crc, csize, usize, nlen, elen = LOCAL_HEADER.unpack_from(data, offset)
    if sig != LOCAL_SIGNATURE:
        return [f"no local file header at offset {offset}"], None
    problems = []
    raw = data[offset + LOCAL_HEADER.size:offset + LOCAL_HEADER.size + nlen]
    name = raw.decode("utf-8" if flags & UTF8_NAME else "cp437", "replace")
    if name != info.orig_filename:
        problems.append(f"local header names it {q(name)}")
    if method != info.compress_type:
        problems.append(f"compression method {method} locally, {info.compress_type} in the directory")
    if not flags & DATA_DESCRIPTOR and ZIP64_MARK not in (csize, usize) and \
            (crc, csize, usize) != (info.CRC, info.compress_size, info.file_size):
        problems.append("CRC or sizes differ between local header and directory")
    return problems, offset + LOCAL_HEADER.size + nlen + elen + info.compress_size


def container(package: Package) -> list[Signal]:
    impossible, mismatched, unsupported, high, oversized, spans = [], [], [], [], [], []
    for info in package.infos:
        name = q(info.filename)
        if info.compress_type not in READABLE_METHODS:
            unsupported.append(f"{name} uses method {info.compress_type}")
        if (info.compress_type == 0 and info.file_size != info.compress_size) or (
                info.compress_type == 8 and info.file_size > DEFLATE_MAX_RATIO * info.compress_size + 4096):
            impossible.append(f"{name} declares {info.file_size} bytes from {info.compress_size} compressed")
        elif info.file_size >= HIGH_RATIO_MIN_BYTES and info.file_size >= HIGH_RATIO * max(info.compress_size, 1):
            high.append(f"{name}: {info.file_size} bytes from {info.compress_size} ({info.file_size // max(info.compress_size, 1)}:1)")
        if info.file_size > opc.MAX_PART_BYTES:
            oversized.append(f"{name} declares {info.file_size} bytes")
        problems, end = _local_header(package, info)
        if problems:
            mismatched.append(f"{name}: {'; '.join(problems)}")
        if end is not None:
            spans.append((info.header_offset, end, info.filename))

    overlapping, furthest = [], None
    for start, end, filename in sorted(spans):
        if furthest and start < furthest[0]:
            overlapping.append(f"{q(filename)} overlaps {q(furthest[1])}")
        if not furthest or end > furthest[0]:
            furthest = (end, filename)

    def signal(rule, severity, summary, evidence):
        return Signal(rule, "office-container", severity, summary, tuple(evidence), ("ZIP central directory",))

    signals = []
    if impossible:
        signals.append(signal("CUSTOM_OFFICE_ZIP_IMPOSSIBLE_SIZE", Severity.LOW,
                              "ZIP entries declare sizes that their compressed data cannot have, so the "
                              "declared metadata is false.", impossible))
    if mismatched:
        signals.append(signal("CUSTOM_OFFICE_ZIP_HEADER_MISMATCH", Severity.LOW,
                              "ZIP local headers contradict the central directory, so different readers can "
                              "extract different content.", mismatched))
    if overlapping:
        signals.append(signal("CUSTOM_OFFICE_ZIP_OVERLAPPING_ENTRIES", Severity.LOW,
                              "ZIP entries share the same compressed data, a construction no normal archiver "
                              "produces (it is used for decompression bombs).", overlapping))
    if unsupported:
        signals.append(signal("CUSTOM_OFFICE_ZIP_UNSUPPORTED_METHOD", Severity.LOW,
                              "ZIP entries use compression Office cannot read, so other tools may see content "
                              "Office does not.", unsupported))
    if high:
        signals.append(signal("CUSTOM_OFFICE_ZIP_HIGH_RATIO", Severity.INFO,
                              f"Large parts are compressed more than {HIGH_RATIO}:1 (common for repetitive XML).",
                              high))
    if oversized:
        signals.append(signal("CUSTOM_OFFICE_ZIP_OVERSIZED_PART", Severity.INFO,
                              f"Parts declare more than {opc.MAX_PART_BYTES} bytes uncompressed; this detector does "
                              "not decompress them.", oversized))
    return signals


# ----------------------------------------------------------------------------- entry point


def analyse(package: Package) -> list[Signal]:
    main = main_document(package)
    declared, by_path = office_family(main)
    if declared or by_path:
        signals = declaration(package, main) + relationships(package)
    else:
        signals = []
        reason = (f"main document declared as {q(main.content_type or 'nothing')}" if main.part
                  else "no main document relationship resolves to a part")
        package.coverage.append(f"not a Word, Excel or PowerPoint package ({reason}); only ZIP container checks applied")
    signals += container(package)
    if package.coverage:
        signals.append(Signal("CUSTOM_OFFICE_COVERAGE_LIMITED", "office-coverage", Severity.INFO,
                              "The custom detector could not analyse every part of this package.",
                              tuple(dict.fromkeys(package.coverage))))
    return signals
