"""OOXML package inspection for the custom detector (Open Packaging Conventions, ECMA-376 Part 2).

The FilesMagic capstone's own reader. It uses the standard library's zipfile and defusedxml (DTDs
and entities rejected), not the Office scanner or oletools, and reads the package the way an
Office application resolves it: through [Content_Types].xml and relationships, never through
the upload's filename.

What it reads:
  - the ZIP central directory and local file headers (metadata only, nothing decompressed);
  - [Content_Types].xml: Default (by extension) and Override (by part name) declarations;
  - every relationship part (_rels/.rels and <dir>/_rels/<part>.rels): Id, Type, Target and
    TargetMode, with internal targets resolved relative to their source part (Part 2, 9.3);
  - the main document: the package relationship of type officeDocument (Transitional or
    Strict) and its declared content type;
  - on request, the bytes of individual parts, within the limits below.

Essential parts ([Content_Types].xml and relationship parts) that cannot be read make the
document unanalysable: CustomScanError, so the scan is UNABLE_TO_SCAN, never SAFE. Content parts
that cannot be read (too large, unsupported compression, encrypted ZIP entry) are recorded in
`coverage` instead. Nothing is executed, extracted to disk or fetched; external relationship
targets are only read as text.
"""

import io
import re
import zipfile
from dataclasses import dataclass, field
from urllib.parse import unquote

import defusedxml.ElementTree as SafeET

from app.scanners.custom.errors import CustomScanError

MAX_ENTRIES = 5000  # ZIP entries; real documents have tens to a few hundred
MAX_RELATIONSHIPS = 100_000  # a worksheet with tens of thousands of hyperlinks is benign
# ponytail: 16 MiB holds ~100k relationships (~160 bytes each); measured ~0.35 s and ~58 MiB peak at
# that ceiling on a Windows dev laptop. Recalibrate on the Linux VM with the benign corpus.
MAX_XML_PART_BYTES = 16 * 1024 * 1024  # [Content_Types].xml or one relationship part, decompressed
MAX_PART_BYTES = 32 * 1024 * 1024  # any other part read for analysis, decompressed
MAX_READ_BYTES = 64 * 1024 * 1024  # everything decompressed for one document

CONTENT_TYPES = "[content_types].xml"
PACKAGE_RELS = "_rels/.rels"
OFFICE_DOCUMENT = {
    "http://schemas.openxmlformats.org/officedocument/2006/relationships/officedocument",
    "http://purl.oclc.org/ooxml/officedocument/relationships/officedocument",  # Strict
}
READABLE_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}  # all that Office itself supports
MALFORMED = CustomScanError.malformed_causes  # wrapped below, so the worker reports malformed_input

_RELS_PART = re.compile(r"^((?:.*/)?)_rels/([^/]*)\.rels$", re.IGNORECASE)  # "_rels" as a whole segment
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def key(name: str) -> str:
    """Part names are compared case-insensitively and without percent-encoding (Part 2, 9.1.1)."""
    return unquote(name).lstrip("/").lower()


def is_package(data: bytes) -> bool:
    return data.startswith(b"PK\x03\x04")


@dataclass
class Relationship:
    source: str  # key of the source part; "" for the package itself
    rels_part: str  # name of the relationship part it was declared in, as stored
    id: str
    type: str  # lower case
    target: str  # as written
    external: bool
    resolved: str | None  # key of the target part; None if external or not a valid part name


@dataclass
class MainDocument:
    relationships: list[Relationship]  # officeDocument relationships of the package
    part: str | None  # key of the main part, if exactly one exists
    content_type: str | None


@dataclass
class Package:
    data: bytes
    zf: zipfile.ZipFile
    infos: list[zipfile.ZipInfo]
    parts: dict[str, zipfile.ZipInfo]  # key -> first entry with that name (directories excluded)
    defaults: dict[str, str] = field(default_factory=dict)  # extension -> content type (lower case)
    overrides: dict[str, str] = field(default_factory=dict)  # part key -> content type (lower case)
    declaration_conflicts: list[str] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    rels_sources: dict[str, str] = field(default_factory=dict)  # relationship part key -> source key
    coverage: list[str] = field(default_factory=list)  # what could not be analysed, and why
    budget: int = field(default_factory=lambda: MAX_READ_BYTES)  # read at creation, not import

    def name(self, part: str) -> str:
        """The part name as stored in the ZIP, for evidence."""
        info = self.parts.get(part)
        return info.filename if info else part

    def content_type(self, part: str) -> str | None:
        if part in self.overrides:
            return self.overrides[part]
        ext = part.rsplit(".", 1)[-1] if "." in part.rsplit("/", 1)[-1] else ""
        return self.defaults.get(ext)

    def read(self, part: str, limit: int, required: bool) -> bytes | None:
        """Decompress one part within `limit` and the document budget. If it cannot be read, an
        essential (required) part raises CustomScanError and any other part returns None with
        the reason recorded in `coverage`."""
        info = self.parts[part]
        reason = None
        if info.flag_bits & 0x1:
            reason = "the ZIP entry is encrypted"
        elif info.compress_type not in READABLE_METHODS:
            reason = f"unsupported ZIP compression method {info.compress_type}"
        elif info.file_size > min(limit, self.budget):
            reason = f"declared size {info.file_size} bytes exceeds the analysis limit"
        if reason:
            if required:
                raise CustomScanError(f"cannot read {info.filename[:80]!r}: {reason}")
            self.coverage.append(f"{info.filename[:80]!r} not read: {reason}")
            return None
        try:
            with self.zf.open(info) as f:
                data = f.read(limit + 1)  # zipfile also stops at the declared size
        except MALFORMED as e:
            raise CustomScanError(f"ZIP entry {info.filename[:80]!r} cannot be decompressed") from e
        if len(data) > limit:
            raise CustomScanError(f"ZIP entry {info.filename[:80]!r} decompresses beyond its declared size")
        self.budget -= len(data)
        return data


def _xml_elements(data: bytes, what: str):
    """(local tag name, attributes) of every element; DTDs and entities are rejected."""
    try:
        for _, el in SafeET.iterparse(io.BytesIO(data), events=("end",), forbid_dtd=True):
            yield el.tag.rsplit("}", 1)[-1], dict(el.attrib)
            el.clear()
    except MALFORMED as e:
        raise CustomScanError(f"{what} is not well-formed XML") from e


def resolve(source: str, target: str) -> str | None:
    """Key of the part an internal relationship target names, relative to its source part
    (Part 2, 9.3), or None if it is not a part name inside the package."""
    target = target.split("#", 1)[0]
    if not target or _SCHEME.match(target) or "\\" in target:
        return None
    base = "" if target.startswith("/") or "/" not in source else source.rsplit("/", 1)[0] + "/"
    segments: list[str] = []
    for seg in (base + target.lstrip("/")).split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not segments:
                return None  # above the package root
            segments.pop()
        else:
            segments.append(seg)
    return key("/".join(segments)) if segments else None


def rels_part_for(part: str) -> str:
    """Key of the relationship part that belongs to `part` ("" = the package)."""
    if not part:
        return PACKAGE_RELS
    head, _, tail = part.rpartition("/")
    return f"{head + '/' if head else ''}_rels/{tail}.rels"


def _content_types(package: Package) -> None:
    data = package.read(CONTENT_TYPES, MAX_XML_PART_BYTES, required=True)
    for tag, attrs in _xml_elements(data, "[Content_Types].xml"):
        if tag == "Default":
            name, table = attrs.get("Extension", "").lower(), package.defaults
        elif tag == "Override":
            name, table = key(attrs.get("PartName", "")), package.overrides
        else:
            continue
        content_type = attrs.get("ContentType", "").strip().lower()
        if name in table and table[name] != content_type:
            package.declaration_conflicts.append(f"{tag} {name!r}: {table[name]!r} and {content_type!r}")
        table.setdefault(name, content_type)  # first declaration wins, as in System.IO.Packaging


def _relationships(package: Package) -> None:
    for part, info in package.parts.items():
        m = _RELS_PART.match(part)
        if not m:
            continue
        source = m.group(1) + m.group(2)
        package.rels_sources[part] = source
        data = package.read(part, MAX_XML_PART_BYTES, required=True)
        for tag, attrs in _xml_elements(data, f"relationship part {info.filename[:80]!r}"):
            if tag != "Relationship":
                continue
            external = attrs.get("TargetMode", "").lower() == "external"
            target = attrs.get("Target", "")
            package.relationships.append(Relationship(
                source=source, rels_part=info.filename, id=attrs.get("Id", ""),
                type=attrs.get("Type", "").strip().lower(), target=target, external=external,
                resolved=None if external else resolve(source, target)))
            if len(package.relationships) > MAX_RELATIONSHIPS:
                raise CustomScanError(f"package declares more than {MAX_RELATIONSHIPS} relationships")


def open_package(data: bytes) -> Package | None:
    """The package, or None if `data` is not an OPC package (no [Content_Types].xml)."""
    if not is_package(data):
        return None
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except MALFORMED as e:
        if b"[Content_Types].xml" in data:  # claims to be an Office package: fail closed
            raise CustomScanError("malformed OOXML container") from e
        return None
    if len(infos) > MAX_ENTRIES:
        raise CustomScanError(f"package has more than {MAX_ENTRIES} ZIP entries")
    parts: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        if not info.filename.endswith("/"):
            parts.setdefault(key(info.filename), info)
    if CONTENT_TYPES not in parts:
        return None
    package = Package(data, zf, infos, parts)
    _content_types(package)
    _relationships(package)
    return package


def main_document(package: Package) -> MainDocument:
    """The officeDocument relationships and the first of their targets that exists (several
    relationships are reported as ambiguous by C4; this one is analysed)."""
    rels = [r for r in package.relationships if r.source == "" and r.type in OFFICE_DOCUMENT and not r.external]
    part = next((r.resolved for r in rels if r.resolved in package.parts), None)
    return MainDocument(rels, part, package.content_type(part) if part else None)
