"""Synthetic Office fixtures built in memory for tests.

These are minimal, inert containers: an OLE2 compound file with chosen stream names
and an OOXML-style ZIP package. They contain no macro code, no executable content and
no exploit; they only carry the structural markers the Office scanner inspects.
"""

import io
import struct
import uuid
import zipfile

ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF
SECTOR = 512


class _Node:
    def __init__(self, name, kind, data=b""):
        self.name, self.kind, self.data, self.children, self.clsid = name, kind, data, [], None


def make_ole(streams: dict[str, bytes], clsids: dict[str, str] | None = None) -> bytes:
    """Build a version-3 compound file. Paths use '/', storages are implied.

    Every stream is padded to at least 4096 bytes so it lives in regular sectors
    (no mini stream needed), which keeps this writer small.
    """
    root = _Node("Root Entry", 5)
    index = {"": root}
    for path, data in streams.items():
        parts = path.split("/")
        for depth in range(1, len(parts)):
            key = "/".join(parts[:depth])
            if key not in index:
                index[key] = _Node(parts[depth - 1], 1)
                index["/".join(parts[: depth - 1])].children.append(index[key])
        node = _Node(parts[-1], 2, data.ljust(max(4096, len(data)), b"\0"))
        index["/".join(parts[:-1])].children.append(node)
        index[path] = node
    for path, clsid in (clsids or {}).items():
        index[path].clsid = clsid

    nodes = []

    def walk(n):
        nodes.append(n)
        for c in n.children:
            walk(c)

    walk(root)
    ids = {id(n): i for i, n in enumerate(nodes)}

    sectors, fat = [], []
    starts = {}
    for n in nodes:
        if n.kind == 2:
            data = n.data.ljust(-(-len(n.data) // SECTOR) * SECTOR, b"\0")
            starts[id(n)] = len(sectors)
            count = len(data) // SECTOR
            for i in range(count):
                sectors.append(data[i * SECTOR:(i + 1) * SECTOR])
                fat.append(len(sectors) if i < count - 1 else ENDOFCHAIN)

    entries = []
    for n in nodes:
        name = n.name.encode("utf-16-le") + b"\0\0"
        child = ids[id(n.children[0])] if n.children else NOSTREAM
        entry = bytearray(128)
        entry[0:len(name)] = name
        struct.pack_into("<HBB", entry, 64, len(name), n.kind, 1)
        struct.pack_into("<III", entry, 68, NOSTREAM, NOSTREAM, child)
        if n.clsid:
            entry[80:96] = uuid.UUID(n.clsid).bytes_le
        start = starts.get(id(n), ENDOFCHAIN if n.kind == 5 else 0)
        struct.pack_into("<II", entry, 116, start, len(n.data) if n.kind == 2 else 0)
        entries.append(entry)
    # Siblings as a right-linked chain under each parent.
    for n in nodes:
        for a, b in zip(n.children, n.children[1:]):
            struct.pack_into("<I", entries[ids[id(a)]], 72, ids[id(b)])
    while len(entries) % 4:
        empty = bytearray(128)
        struct.pack_into("<III", empty, 68, NOSTREAM, NOSTREAM, NOSTREAM)
        entries.append(empty)

    dir_start = len(sectors)
    dir_count = len(entries) // 4
    for i in range(dir_count):
        sectors.append(b"".join(entries[i * 4:(i + 1) * 4]))
        fat.append(len(sectors) if i < dir_count - 1 else ENDOFCHAIN)

    fat_count = 1
    while len(sectors) + fat_count > fat_count * 128:
        fat_count += 1
    fat_start = len(sectors)
    fat += [FATSECT] * fat_count
    fat += [FREESECT] * (fat_count * 128 - len(fat))
    for i in range(fat_count):
        sectors.append(struct.pack("<128I", *fat[i * 128:(i + 1) * 128]))

    header = bytearray(SECTOR)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<HHHHH", header, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<IIIIIIIII", header, 40, 0, fat_count, dir_start, 0, 4096, ENDOFCHAIN, 0, ENDOFCHAIN, 0)
    difat = [fat_start + i for i in range(fat_count)] + [FREESECT] * (109 - fat_count)
    struct.pack_into("<109I", header, 76, *difat)
    return bytes(header) + b"".join(sectors)


def word_document_stream(encrypted: bool = False) -> bytes:
    """FIB base of a Word 97 WordDocument stream; only the encryption flag matters here."""
    flags = 0x0100 if encrypted else 0  # FibBase.fEncrypted
    return struct.pack("<HHHHHH", 0xA5EC, 0x00C1, 0, 0x0409, 0, flags)


def ole10native(filename: str, payload: bytes = b"inert test bytes") -> bytes:
    """\\x01Ole10Native stream of an OLE Package object; payload is plain text."""
    body = (
        struct.pack("<H", 2)
        + filename.encode() + b"\0"  # label
        + ("C:\\temp\\" + filename).encode() + b"\0"  # source path
        + struct.pack("<HH", 0, 3)
        + struct.pack("<I", len(filename) + 9) + ("C:\\temp\\" + filename).encode() + b"\0"
        + struct.pack("<I", len(payload)) + payload
    )
    return struct.pack("<I", len(body)) + body


CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    "</Types>"
)
RELS_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL_TYPE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"
W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def rels(*relationships: tuple[str, str, bool]) -> str:
    """relationships: (type suffix, target, external?)"""
    external_attr = ' TargetMode="External"'
    items = "".join(
        f'<Relationship Id="rId{i}" Type="{REL_TYPE}{t}" Target="{target}"{external_attr if external else ""}/>'
        for i, (t, target, external) in enumerate(relationships, 1)
    )
    return f'<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="{RELS_NS}">{items}</Relationships>'


def word_body(inner: str = "<w:p><w:r><w:t>Hello</w:t></w:r></w:p>") -> str:
    return f'<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="{W_NS}"><w:body>{inner}</w:body></w:document>'


def make_ooxml(parts: dict[str, str | bytes], kind: str = "word") -> bytes:
    """A minimal OOXML package: [Content_Types].xml, root rels and the given parts."""
    main = {"word": "word/document.xml", "xl": "xl/workbook.xml", "ppt": "ppt/presentation.xml"}[kind]
    files = {
        "[Content_Types].xml": CONTENT_TYPES,
        "_rels/.rels": rels(("officeDocument", main, False)),
        main: word_body() if kind == "word" else f'<?xml version="1.0"?><{kind}Root/>',
    }
    files.update(parts)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()
