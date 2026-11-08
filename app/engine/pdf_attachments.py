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
3. Each embedded stream is decoded under pypdf's stream limits (app.scanners.pdf.PDF_LIMITS, which
   the caller applies) and its declared /Params /Size, if any, must match.
4. A stream is verified only as an OpenDocument package without code: a ZIP whose first member is
   an uncompressed `mimetype` naming an ODF text, spreadsheet, presentation or drawing; every
   member on a fixed list of parts that hold content, styles, metadata, settings, a thumbnail or
   raster pictures (no Basic/ or Scripts/ macro libraries, no embedded objects, no SVG); no
   encryption; every member at most MAX_MEMBER bytes and MAX_PACKAGE in all; and no XML part that
   binds a script or macro (office:event-listeners, script:event-listener, vnd.sun.star.script,
   macro:) or links outside the package (xlink:href other than an internal, http, https or mailto
   reference). Every name of its file specification must end in that type's extension, since a
   reader saves the attachment under that name and the system opens it by extension.
   This is the LibreOffice "hybrid PDF" (the editable document kept inside its PDF export).

Anything else (another type, an orphan stream, a parse problem) is "not verified" with the reason:
a verdict about what the attachment is not, never that it is safe.
"""

import io
import re
import zipfile
from dataclasses import dataclass

from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, StreamObject

from app.scanners.pdf import MAX_DEPTH, MAX_OBJECTS, clean, text_of

TOKEN = b"/EmbeddedFile"
ODF_TYPES = {f"application/vnd.oasis.opendocument.{k}": v for k, v in
             (("text", "odt"), ("spreadsheet", "ods"), ("presentation", "odp"), ("graphics", "odg"))}
ODF_PARTS = re.compile(r"mimetype|content\.xml|styles\.xml|meta\.xml|settings\.xml|manifest\.rdf|META-INF/manifest\.xml"
                       r"|Thumbnails/thumbnail\.png|Pictures/[^/]+\.(?:png|jpe?g|gif)|Configurations2/(?:[^/]+/)*")
# office:scripts is only the container (LibreOffice writes it empty); code is an office:script child
# or an event listener (ODF 1.3 part 3, 3.12-3.13; 10.3.x script:event-listener).
ODF_CODE = re.compile(rb"office:event-listeners|script:event-listener|vnd\.sun\.star\.script|macro:|<office:script[\s/>]")
HREF = re.compile(rb'xlink:href\s*=\s*["\']([^"\']*)')
SAFE_HREF = re.compile(rb"#|\./|Pictures/|https?://|mailto:", re.IGNORECASE)
NAME_KEYS = ("/UF", "/F", "/Unix", "/DOS", "/Mac")
MAX_MEMBERS = 100
MAX_MEMBER = 4 * 1024 * 1024
MAX_PACKAGE = 16 * 1024 * 1024


@dataclass(frozen=True)
class Attachment:
    name: str
    verified: str = ""  # what it was verified to be, or
    reason: str = ""  # why it was not


def _resolve(value):
    return value.get_object() if isinstance(value, IndirectObject) else value


def odf_without_code(data: bytes) -> tuple[str, str]:
    """(ODF extension, "") if `data` is an OpenDocument package without code, else ("", why)."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError) as e:
        return "", f"not an OpenDocument package ({type(e).__name__})"
    if not infos or len(infos) > MAX_MEMBERS:
        return "", f"{len(infos)} ZIP members"
    first = infos[0]
    if first.filename != "mimetype" or first.compress_type != zipfile.ZIP_STORED or first.file_size > 100:
        return "", "no uncompressed mimetype member first"
    kind = ODF_TYPES.get(zf.read(first).decode("ascii", "replace").strip())
    if not kind:
        return "", "mimetype is not an OpenDocument text, spreadsheet, presentation or drawing"
    if odd := [i.filename for i in infos if not ODF_PARTS.fullmatch(i.filename)]:
        return "", f"part {clean(odd[0], 60)!r} is not one that holds only content (macros, scripts or objects)"
    if any(i.flag_bits & 0x1 for i in infos) or sum(i.file_size for i in infos) > MAX_PACKAGE \
            or any(i.file_size > MAX_MEMBER for i in infos):
        return "", "encrypted or too large to read"
    for info in infos:
        if not info.filename.endswith((".xml", ".rdf")):
            continue
        with zf.open(info) as f:
            xml = f.read(MAX_MEMBER + 1)
        if len(xml) > MAX_MEMBER:
            return "", f"{info.filename} is larger than it declares"
        if info.filename == "META-INF/manifest.xml" and b"encryption-data" in xml:
            return "", "the package is encrypted"
        if m := ODF_CODE.search(xml):
            return "", f"{info.filename} binds a script or macro ({m.group().decode()})"
        if bad := [h for h in HREF.findall(xml) if h and not SAFE_HREF.match(h)]:
            return "", f"{info.filename} links outside the package ({clean(bad[0].decode('latin-1'), 60)!r})"
    return kind, ""


def inspect_stream(stream, names: list[str]) -> Attachment:
    label = clean(names[0] if names else "(unnamed)", 60)
    if not isinstance(stream, StreamObject):
        return Attachment(label, reason="its /EF entry is not a stream")
    data = stream.get_data()  # bounded by the caller's PDF_LIMITS
    params = _resolve(stream.get("/Params"))
    size = _resolve(params.get("/Size")) if isinstance(params, DictionaryObject) else None
    if size is not None and size != len(data):
        return Attachment(label, reason=f"declares {size} bytes but holds {len(data)}")
    kind, why = odf_without_code(data)
    if not kind:
        return Attachment(label, reason=why)
    if not names or any(not n.lower().endswith("." + kind) for n in names):
        return Attachment(label, reason=f"an OpenDocument .{kind} package under a name that does not end in .{kind}")
    return Attachment(label, verified=f"OpenDocument .{kind} without macros, scripts or external links "
                                      f"({len(data)} bytes)")


def inspect(reader, data: bytes) -> tuple[list[Attachment], str]:
    """Every attachment, and a problem that keeps the list from being complete ("" if none)."""
    objects = [(num, gen) for gen, table in reader.xref.items() for num in table] + \
              [(num, 0) for num in reader.xref_objStm]
    if len(objects) > MAX_OBJECTS:
        return [], f"more than {MAX_OBJECTS} objects"
    spans = sorted((off, data.find(b"endobj", off)) for table in reader.xref.values() for off in table.values())
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
    found, used = [], set()
    for spec in specs:
        names = [text_of(_resolve(spec[k]), 1000) for k in NAME_KEYS if k in spec]
        ef = _resolve(spec["/EF"])
        refs = list(ef.values()) if isinstance(ef, DictionaryObject) else []
        if not refs:
            found.append(Attachment(clean(names[0] if names else "(unnamed)", 60), reason="its /EF entry is empty"))
        for ref in refs:
            if isinstance(ref, IndirectObject):
                used.add((ref.idnum, ref.generation))
            found.append(inspect_stream(_resolve(ref), names))
    found += [Attachment(f"object {n} {g}", reason="an embedded file stream no file specification names")
              for n, g in sorted(streams - used)]
    return found, ""
