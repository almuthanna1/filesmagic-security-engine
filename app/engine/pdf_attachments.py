"""What a PDF's attachments are, from their bytes (custom engine).

The PDF scanner and the reference YARA-X rule report any attachment (PDF_EMBEDDED_FILE,
PDF_Embedded_File, LOW) and call one dangerous only by its declared name or MIME type, which the
file's author chooses. This reads the attachments themselves, without opening them in any
application:

1. Every object in the cross-reference table is visited (not only those reachable from the
   catalog, which is all the PDF scanner walks), with every dictionary nested in it: each file
   specification with /EF, and each stream with /Type /EmbeddedFile.
2. Every /EmbeddedFile token in the raw bytes must lie inside an object of that table; one outside
   (an older revision, bytes no reader parses) means something was not seen.
   Every object header (`N G obj`) in the raw bytes must be one the table points to: an object
   of an older revision, or one only a repairing reader would find, may be an attachment too.
3. Each embedded stream is decoded under pypdf's stream limits (app.scanners.pdf.PDF_LIMITS, which
   the caller applies), at most MAX_FILES of them and MAX_FILE_BYTES decoded in all, and its
   declared /Params /Size, if any, must match.
4. A stream is verified only as an OpenDocument package without code or automatically loaded
   content (odf_without_code): what it is, from its bytes, never from its name or MIME type.
   Every name of its file specification must end in that type's extension and hold no control or
   formatting characters (x.exe<NUL>.odt), since a reader saves it under that name and the
   system opens it by extension. This is the LibreOffice "hybrid PDF" (the editable document
   kept inside its PDF export).

Anything else (another type, an orphan stream, a parse problem) is "not verified" with the reason:
a verdict about what the attachment is not, never that it is safe. Not examined: the contents of
the raster pictures beyond their signature, and anything outside the attachments (fonts, images,
3D or media streams of the PDF itself), which the attachment findings do not cover either.
"""

import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass

import defusedxml.ElementTree as SafeET
from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject

from app.scanners.office import unsafe_member_name
from app.scanners.pdf import MAX_DEPTH, MAX_OBJECTS, clean, text_of

TOKEN = b"/EmbeddedFile"
OBJECT_HEADER = re.compile(rb"(?<![0-9])[0-9]+\s+[0-9]+\s+obj\b")
ODF_TYPES = {f"application/vnd.oasis.opendocument.{k}": v for k, v in
             (("text", "odt"), ("spreadsheet", "ods"), ("presentation", "odp"), ("graphics", "odg"))}
ODF_PARTS = re.compile(r"mimetype|content\.xml|styles\.xml|meta\.xml|settings\.xml|manifest\.rdf|META-INF/manifest\.xml"
                       r"|Thumbnails/thumbnail\.png|Pictures/[^/]+\.(?:png|jpe?g|gif)|Configurations2/(?:[^/]+/)*")
RASTER = {"png": (b"\x89PNG\r\n\x1a\n",), "jpg": (b"\xff\xd8\xff",), "jpeg": (b"\xff\xd8\xff",),
          "gif": (b"GIF87a", b"GIF89a")}
# Elements that hold or run code, bind events, or embed objects or data from elsewhere (ODF 1.3
# part 3: office:script, text:script, office:event-listeners, script:/presentation:event-listener,
# text:execute-macro, draw:applet/plugin/object/object-ole/floating-frame, office:binary-data, the
# DDE elements). Matched by local name in any namespace, so a prefix or extension namespace
# cannot hide them. office:scripts, the empty container LibreOffice writes, may have no children.
ODF_ACTIVE = {"script", "event-listener", "event-listeners", "execute-macro", "applet", "plugin", "object",
              "object-ole", "floating-frame", "binary-data", "dde-source", "dde-connection-decl", "dde-link"}
ENCRYPTION = {"encryption-data", "keyinfo"}  # manifest: ODF password and OpenPGP encryption
XLINK_HREF, XML_BASE = "{http://www.w3.org/1999/xlink}href", "{http://www.w3.org/XML/1998/namespace}base"
RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"  # rdf:about/resource: identifiers, never fetched
# text:a and draw:a are hyperlinks: followed only when the user clicks one (LibreOffice: Ctrl+click).
PASSIVE_LINK = re.compile(r"(?:https?://|mailto:)\S", re.IGNORECASE)
# An attribute value that names something outside the package, wherever it appears.
EXTERNAL_VALUE = re.compile(r".*://|[\\/]{2}|[a-z]:[\\/]|(?:file|vnd\.sun\.star\.[a-z]+|macro|javascript|vbscript|data):",
                            re.IGNORECASE | re.DOTALL)
NAME_KEYS = ("/UF", "/F", "/Unix", "/DOS", "/Mac")
MAX_MEMBERS = 100
MAX_MEMBER = 4 * 1024 * 1024
MAX_PACKAGE = 16 * 1024 * 1024  # uncompressed bytes read, for all attachments of one PDF together
MAX_FILES = 100  # embedded streams decoded per PDF
MAX_FILE_BYTES = 64 * 1024 * 1024  # decoded embedded streams per PDF, in all


@dataclass(frozen=True)
class Attachment:
    name: str
    verified: str = ""  # what it was verified to be, or
    reason: str = ""  # why it was not


def _resolve(value):
    return value.get_object() if isinstance(value, IndirectObject) else value


def odf_without_code(data: bytes, budget: list[int]) -> tuple[str, str, int]:
    """(ODF extension, "", passive hyperlinks) if `data` is an OpenDocument package without code or
    automatically loaded content, else ("", why, 0). Any failure is a reason, never a pass.
    `budget`: uncompressed bytes left to read, shared by the attachments of one PDF.

    The package: one ZIP from byte 0 to the end, as many local and central headers as members, no
    archive comment (no second archive inside or around it); the uncompressed `mimetype` first, at
    byte 30 as ODF requires, naming an ODF text, spreadsheet, presentation or drawing; unique, safe
    member names, every one on ODF_PARTS (no Basic/ or Scripts/ macro libraries, no embedded objects,
    no SVG or metafiles); pictures that start with their format's signature; no encryption.
    Every XML part is parsed (defusedxml, no DTD), whatever its encoding or namespace prefixes, and
    rejected if an element is in ODF_ACTIVE or encrypts the package, an xml:base changes how
    references resolve, an attribute other than an RDF identifier names something outside the package
    (EXTERNAL_VALUE), or an xlink:href is neither a part of this package nor, on a hyperlink (a), an
    http, https or mailto link. Hyperlinks are not loaded; they are counted for the evidence."""
    try:
        return _odf(data, budget)
    except Exception as e:  # malformed ZIP, compression, CRC or XML: not verified
        return "", f"could not be read as an OpenDocument package ({type(e).__name__}: {clean(e, 80)})", 0


def _odf(data: bytes, budget: list[int]) -> tuple[str, str, int]:
    if not data.startswith(b"PK\x03\x04") or data[30:38] != b"mimetype":
        return "", "not an OpenDocument package (no mimetype member at the start)", 0
    zf = zipfile.ZipFile(io.BytesIO(data))
    infos = zf.infolist()
    names = [i.filename for i in infos]
    if not infos or len(infos) > MAX_MEMBERS:
        return "", f"{len(infos)} ZIP members", 0
    if (data[-22:-18] != b"PK\x05\x06" or data.count(b"PK\x03\x04") != len(infos)
            or data.count(b"PK\x01\x02") != len(infos) or infos[0].header_offset != 0):
        return "", "the ZIP holds data its directory does not list (another archive, a comment or hidden members)", 0
    if len({n.lower() for n in names}) != len(names) or any(unsafe_member_name(n) for n in names):
        return "", "duplicate or unsafe member names", 0
    first = infos[0]
    if first.filename != "mimetype" or first.compress_type != zipfile.ZIP_STORED or first.file_size > 100:
        return "", "no uncompressed mimetype member first", 0
    kind = ODF_TYPES.get(zf.read(first).decode("ascii", "replace").strip())
    if not kind:
        return "", "mimetype is not an OpenDocument text, spreadsheet, presentation or drawing", 0
    if odd := [n for n in names if not ODF_PARTS.fullmatch(n)]:
        return "", f"part {clean(odd[0], 60)!r} is not one that holds only content (macros, scripts or objects)", 0
    budget[0] -= sum(i.file_size for i in infos)
    if any(i.flag_bits & 0x1 for i in infos) or any(i.file_size > MAX_MEMBER for i in infos) or budget[0] < 0:
        return "", "encrypted or too large to read", 0
    links = 0
    for info in infos:
        ext = info.filename.rsplit(".", 1)[-1].lower()
        if ext in RASTER:
            with zf.open(info) as f:
                if not f.read(8).startswith(RASTER[ext]):
                    return "", f"{clean(info.filename, 60)} is not the {ext.upper()} picture its name says", 0
            continue
        if ext not in ("xml", "rdf"):
            continue
        with zf.open(info) as f:  # ZipExtFile stops at the declared size and checks the CRC
            why, n = _odf_xml(f, info.filename, set(names))
        if why:
            return "", f"{clean(info.filename, 60)}: {why}", 0
        links += n
    return kind, "", links


def _odf_xml(f, part: str, members: set[str]) -> tuple[str, int]:
    """("", passive hyperlinks) for an XML part without code or external references, else (why, 0)."""
    stack, links = [], 0
    for event, el in SafeET.iterparse(f, events=("start", "end"), forbid_dtd=True):
        local = el.tag.rsplit("}", 1)[-1]
        if event == "end":
            stack.pop()
            el.clear()
            continue
        if local in ODF_ACTIVE or (stack and stack[-1] == "scripts"):
            return f"element {clean(local, 40)} binds a script or macro, or embeds an object or external data", 0
        if local in ENCRYPTION:
            return "the package is encrypted", 0
        stack.append(local)
        for key, value in el.attrib.items():
            value = value.strip()
            if key == XML_BASE:
                return "an xml:base attribute changes where references point", 0
            if key == XLINK_HREF:
                if value.startswith("#") or (value.removeprefix("./") in members and value):
                    continue
                if local == "a" and PASSIVE_LINK.match(value):
                    links += 1
                    continue
                return f"{clean(local, 40)} xlink:href {clean(value, 60)!r} refers outside the package", 0
            if not key.startswith(RDF) and EXTERNAL_VALUE.match(value):
                return f"{clean(local, 40)} attribute {clean(key.rsplit('}', 1)[-1], 40)}={clean(value, 60)!r} " \
                       "refers outside the package", 0
    return "", links


def _plain_name(name: str) -> bool:
    """No control or formatting characters (NUL, bidirectional overrides, zero-width marks)."""
    return not any(unicodedata.category(c) in ("Cc", "Cf") for c in name)


def inspect_stream(stream, names: list[str], budget: list[int], decoded: list[int]) -> Attachment:
    label = clean(names[0] if names else "(unnamed)", 60)
    if not isinstance(stream, StreamObject):
        return Attachment(label, reason="its /EF entry is not a stream")
    data = stream.get_data()  # bounded by the caller's PDF_LIMITS
    decoded[0] += len(data)
    params = _resolve(stream.get("/Params"))
    size = _resolve(params.get("/Size")) if isinstance(params, DictionaryObject) else None
    if size is not None and size != len(data):
        return Attachment(label, reason=f"declares {size} bytes but holds {len(data)}")
    kind, why, links = odf_without_code(data, budget)
    if not kind:
        return Attachment(label, reason=why)
    if not names or any(not n.lower().endswith("." + kind) or not _plain_name(n) for n in names):
        return Attachment(label, reason=f"an OpenDocument .{kind} package under a name that does not end in .{kind} "
                                        "or holds control characters")
    return Attachment(label, verified=f"OpenDocument .{kind} without macros, scripts, embedded objects or "
                                      f"automatically loaded external content ({len(data)} bytes; {links} "
                                      "passive hyperlink(s), followed only on a click)")


def inspect(reader, data: bytes) -> tuple[list[Attachment], str]:
    """Every attachment, and a problem that keeps the list from being complete ("" if none)."""
    objects = [(num, gen) for gen, table in reader.xref.items() for num in table] + \
              [(num, 0) for num in reader.xref_objStm]
    if len(objects) > MAX_OBJECTS:
        return [], f"more than {MAX_OBJECTS} objects"
    # An xref offset may point at whitespace before the object number.
    starts = {off + len(data[off:off + 64]) - len(data[off:off + 64].lstrip())
              for table in reader.xref.values() for off in table.values()}
    if (outside := next((m.start() for m in OBJECT_HEADER.finditer(data) if m.start() not in starts), None)) is not None:
        return [], f"an object at byte {outside} is not one the cross-reference table points to (an older " \
                   "revision, or one only a repairing reader would find)"
    spans = sorted((off, data.find(b"endobj", off)) for off in starts)
    for at in (m.start() for m in re.finditer(re.escape(TOKEN), data)):
        if not any(start <= at < end for start, end in spans):
            return [], f"an {TOKEN.decode()} token at byte {at} lies outside every object the parser reads"
    specs, streams = [], set()
    for num, gen in objects:
        obj = reader.get_object(IndirectObject(num, gen, reader))
        if isinstance(obj, StreamObject) and obj.get("/Type") == "/EmbeddedFile":
            streams.add((num, gen))
        todo = [(obj, 0)]
        while todo:
            node, depth = todo.pop()
            if depth > MAX_DEPTH:
                return [], "an object is nested too deeply"
            if isinstance(node, ArrayObject):
                todo.extend((v, depth + 1) for v in node if not isinstance(v, IndirectObject))
            elif isinstance(node, DictionaryObject):
                if "/EF" in node:
                    specs.append(node)
                todo.extend((v, depth + 1) for v in node.values() if not isinstance(v, IndirectObject))
    found, used, budget, decoded = [], set(), [MAX_PACKAGE], [0]
    for spec in specs:
        names = [text_of(_resolve(spec[k]), 1000) for k in NAME_KEYS if k in spec]
        ef = _resolve(spec["/EF"])
        refs = list(ef.values()) if isinstance(ef, DictionaryObject) else []
        if not refs:
            found.append(Attachment(clean(names[0] if names else "(unnamed)", 60), reason="its /EF entry is empty"))
        for ref in refs:
            if len(found) >= MAX_FILES or decoded[0] > MAX_FILE_BYTES:
                return [], f"more than {MAX_FILES} embedded files or {MAX_FILE_BYTES // 2**20} MB of them to decode"
            if isinstance(ref, IndirectObject):
                used.add((ref.idnum, ref.generation))
            found.append(inspect_stream(_resolve(ref), names, budget, decoded))
    if decoded[0] > MAX_FILE_BYTES:
        return [], f"more than {MAX_FILE_BYTES // 2**20} MB of embedded files to decode"
    found += [Attachment(f"object {n} {g}", reason="an embedded file stream no file specification names")
              for n, g in sorted(streams - used)]
    return found, ""
