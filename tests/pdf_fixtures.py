"""Synthetic PDF fixtures built in memory for tests.

Minimal, inert PDFs: the JavaScript bodies are harmless one-liners like app.alert(1),
"attachments" are short text, and nothing here exploits anything. They only carry the
structures the PDF scanner inspects.
"""

import io
import struct
import zlib

from pypdf import PdfWriter
from pypdf.actions import JavaScript

CATALOG = "<< /Type /Catalog /Pages 2 0 R {extra} >>"
PAGES = "<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
PAGE = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R {extra} >>"
CONTENT = "stream:BT /F1 12 Tf 20 100 Td (Hello world) Tj ET"


def _obj_body(body: str) -> bytes:
    if body.startswith("stream:"):
        data = body[len("stream:"):].encode("latin-1")
        return b"<< /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"
    return body.encode("latin-1")


def make_pdf(catalog_extra: str = "", page_extra: str = "", objects: dict[int, str] | None = None,
             compressed: set[int] = frozenset(), header_offset: int = 0) -> bytes:
    """Build a PDF. Objects 1-4 are catalog, page tree, page and content; `objects` adds
    more (use numbers >= 5). Objects in `compressed` go into a FlateDecode object stream
    referenced from a cross-reference stream, so their dictionaries never appear as raw
    bytes in the file."""
    objs = {1: CATALOG.format(extra=catalog_extra), 2: PAGES, 3: PAGE.format(extra=page_extra), 4: CONTENT}
    objs.update(objects or {})

    out = bytearray(b"x" * header_offset + b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    plain = [n for n in sorted(objs) if n not in compressed]
    for n in plain:
        offsets[n] = len(out)
        out += b"%d 0 obj\n" % n + _obj_body(objs[n]) + b"\nendobj\n"

    if not compressed:
        size = max(objs) + 1
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % size
        for n in range(1, size):
            out += (b"%010d 00000 n \n" % offsets[n]) if n in offsets else b"0000000000 65535 f \n"
        out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (size, xref)
        return bytes(out)

    # Object stream with the compressed objects, then a cross-reference stream.
    members = sorted(compressed)
    bodies = [_obj_body(objs[n]) for n in members]
    header, pos = [], 0
    for n, body in zip(members, bodies):
        header.append(b"%d %d" % (n, pos))
        pos += len(body) + 1
    head = b" ".join(header) + b"\n"
    raw = zlib.compress(head + b"\n".join(bodies) + b"\n")
    objstm, xrefstm = max(objs) + 1, max(objs) + 2
    offsets[objstm] = len(out)
    out += (b"%d 0 obj\n<< /Type /ObjStm /N %d /First %d /Filter /FlateDecode /Length %d >>\nstream\n"
            % (objstm, len(members), len(head), len(raw)) + raw + b"\nendstream\nendobj\n")

    size = xrefstm + 1
    offsets[xrefstm] = len(out)
    rows = [struct.pack(">BIH", 0, 0, 0xFFFF)]
    for n in range(1, size):
        if n in compressed:
            rows.append(struct.pack(">BIH", 2, objstm, members.index(n)))
        elif n in offsets:
            rows.append(struct.pack(">BIH", 1, offsets[n], 0))
        else:
            rows.append(struct.pack(">BIH", 0, 0, 0xFFFF))
    table = b"".join(rows)
    out += (b"%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n"
            % (xrefstm, size, len(table)) + table + b"\nendstream\nendobj\n")
    out += b"startxref\n%d\n%%%%EOF\n" % offsets[xrefstm]
    return bytes(out)


def js_action(code: str = "app.alert(1);") -> str:
    return f"<< /Type /Action /S /JavaScript /JS ({code}) >>"


def uri_link(uri: str) -> dict[int, str]:
    """A link annotation (object 5) on the page pointing to `uri`."""
    return {5: f"<< /Type /Annot /Subtype /Link /Rect [0 0 50 50] /A << /S /URI /URI ({uri}) >> >>"}


def attachment(name: str, mime: str = "/text#2Fplain") -> tuple[str, dict[int, str]]:
    """Catalog extra + objects (5, 6) for one embedded file in the EmbeddedFiles name tree."""
    data = "inert attachment text"
    return (
        "/Names << /EmbeddedFiles << /Names [(f) 5 0 R] >> >>",
        {
            5: f"<< /Type /Filespec /F ({name}) /UF ({name}) /EF << /F 6 0 R >> >>",
            6: f"<< /Type /EmbeddedFile /Subtype {mime} /Length {len(data)} >>\nstream\n{data}\nendstream",
        },
    )


def encrypted_pdf(user_password: str, owner_password: str = "owner") -> bytes:
    writer = PdfWriter()
    writer.add_blank_page(200, 200)
    writer.add_open_action(JavaScript("app.alert(1);"))  # visible to the scanner once decrypted
    writer.encrypt(user_password=user_password, owner_password=owner_password, algorithm="AES-256")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()
