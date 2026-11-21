"""Real, inert VBA projects (MS-OVBA) for end-to-end tests through oletools' real extractor.

A VBA project is an OLE storage: PROJECT (text), VBA/_VBA_PROJECT (P-code cache header), VBA/dir
(compressed project records) and one compressed stream per module. We write only what MS-OVBA
2.3.4 requires for the source to be extracted: no P-code, so Office would have nothing to run
even if it opened the file, and every module is source text with placeholder arguments.

Compression uses MS-OVBA 2.4.1 raw chunks only (flag 0: 4096 bytes stored as-is), the simplest
valid CompressedContainer. Each compressed stream is then at least 4097 bytes, so the OLE writer
in tests/office_fixtures.py never pads it with bytes a decompressor would misread.
"""

import struct

from tests.office_fixtures import make_ole, make_ooxml


def compress(data: bytes) -> bytes:
    """MS-OVBA CompressedContainer of raw chunks; the last chunk is padded with spaces."""
    out = bytearray(b"\x01")
    for i in range(0, max(len(data), 1), 4096):
        out += struct.pack("<H", 0x3FFF) + data[i:i + 4096].ljust(4096, b" ")  # size 4098, signature 0b011, flag 0
    return bytes(out)


def _rec(rid: int, payload: bytes) -> bytes:
    return struct.pack("<HI", rid, len(payload)) + payload


def dir_stream(modules: list[str]) -> bytes:
    d = _rec(0x01, struct.pack("<I", 1))  # PROJECTSYSKIND: 32-bit Windows
    d += _rec(0x02, struct.pack("<I", 0x409)) + _rec(0x14, struct.pack("<I", 0x409))  # LCID, LCIDINVOKE
    d += _rec(0x03, struct.pack("<H", 1252))  # CODEPAGE
    d += _rec(0x04, b"Project")  # NAME
    d += _rec(0x05, b"") + _rec(0x40, b"")  # DOCSTRING (+ unicode)
    d += _rec(0x06, b"") + _rec(0x3D, b"")  # HELPFILEPATH (+ second copy)
    d += _rec(0x07, struct.pack("<I", 0)) + _rec(0x08, struct.pack("<I", 0))  # HELPCONTEXT, LIBFLAGS
    d += struct.pack("<HIIH", 0x09, 4, 1, 0)  # PROJECTVERSION (Reserved=4, major, minor)
    d += _rec(0x0C, b"") + _rec(0x3C, b"")  # CONSTANTS (+ unicode); no REFERENCE records
    d += _rec(0x0F, struct.pack("<H", len(modules))) + _rec(0x13, struct.pack("<H", 0xFFFF))  # MODULES, cookie
    for name in modules:
        raw = name.encode("cp1252")
        d += _rec(0x19, raw)  # MODULENAME
        d += _rec(0x1A, raw) + _rec(0x32, name.encode("utf-16-le"))  # MODULESTREAMNAME (+ unicode)
        d += _rec(0x31, struct.pack("<I", 0))  # MODULEOFFSET: source starts at the stream's first byte
        d += struct.pack("<HI", 0x21, 0)  # MODULETYPE: procedural
        d += struct.pack("<HI", 0x2B, 0)  # module terminator
    d += struct.pack("<HI", 0x10, 0)  # dir terminator
    return compress(d)


def vba_streams(modules: dict[str, str], root: str = "") -> dict[str, bytes]:
    """OLE streams of a VBA project with these (module name -> source) modules, under `root`."""
    project = "".join(f"Module={m}\r\n" for m in modules) + 'Name="Project"\r\n'
    streams = {
        f"{root}PROJECT": project.encode("cp1252"),
        f"{root}VBA/_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00",  # header only: no cached P-code
        f"{root}VBA/dir": dir_stream(list(modules)),
    }
    for name, code in modules.items():
        streams[f"{root}VBA/{name}"] = compress(code.replace("\r\n", "\n").replace("\n", "\r\n").encode("cp1252"))
    return streams


def vba_project(modules: dict[str, str]) -> bytes:
    """vbaProject.bin, as stored in a .docm/.xlsm package."""
    return make_ole(vba_streams(modules))


def docm(modules: dict[str, str]) -> bytes:
    return make_ooxml({"word/vbaProject.bin": vba_project(modules)})
