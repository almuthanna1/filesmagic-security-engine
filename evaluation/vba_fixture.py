"""Build a genuinely benign legacy Word (OLE) document that carries a real, parseable VBA project,
so the evaluation exercises oletools' actual macro-extraction path rather than a mocked result.

The macro is inert: it only adds two integers. It performs no network access, no file-system change,
no process execution and delivers no payload, and it is never executed here. The document is used
only as a static input to the scanners (olevba parses the source; nothing runs it).

The VBA project is assembled from the structures oletools reads (MS-OVBA): a `dir` stream (project
and module records) and a module stream holding the source. Both are stored as a CompressedContainer
of uncompressed 4096-byte chunks (MS-OVBA 2.4.1.3.3), so no LZ compressor is needed and the bytes
round-trip exactly through oletools.olevba.decompress_stream. Deterministic: the same bytes every
build (verified by its committed SHA-256 in evaluation/expectations/inert-benign-macro-doc.json).

Nothing here touches app/. This is evaluation-only test-fixture code.
"""

import struct

from tests.office_fixtures import make_ole

# One inert standard module. AutoOpen is a real Word auto-execution entry point, included so the
# scanners' autoexec detection runs on genuine source; the body only computes 2 + 2.
MODULE_NAME = "Module1"
SOURCE = (
    'Attribute VB_Name = "Module1"\r\n'
    "Sub AutoOpen()\r\n"
    "    Dim result As Integer\r\n"
    "    result = Compute()\r\n"
    "End Sub\r\n"
    "\r\n"
    "Function Compute() As Integer\r\n"
    "    Compute = 2 + 2\r\n"
    "End Function\r\n"
)
PROJECT_STREAM = (
    'ID="{00000000-0000-0000-0000-000000000000}"\r\n'
    "Module=Module1\r\n"
    'Name="Project"\r\n'
    'HelpContextID="0"\r\n'
    'VersionCompatible32="393222000"\r\n'
)


def _u16(v: int) -> bytes:
    return struct.pack("<H", v)


def _u32(v: int) -> bytes:
    return struct.pack("<L", v)


def _container(data: bytes, fill: bytes) -> bytes:
    """A CompressedContainer of uncompressed chunks (MS-OVBA 2.4.1.1.1). Each chunk is exactly 4096
    decompressed bytes with header 0x3FFF (signature 0b011, flag 0). `fill` pads the final chunk."""
    padded = data.ljust(((len(data) // 4096) + 1) * 4096, fill) if len(data) % 4096 or not data else data
    out = b"\x01"
    for i in range(0, len(padded), 4096):
        out += _u16(0x3FFF) + padded[i : i + 4096]
    return out


def _dir_stream() -> bytes:
    name, modname = b"Project", MODULE_NAME.encode("ascii")
    modname_u = MODULE_NAME.encode("utf-16le")
    d = b""
    d += _u16(0x0001) + _u32(4) + _u32(0x00000001)                 # PROJECTSYSKIND: 32-bit Windows
    d += _u16(0x0002) + _u32(4) + _u32(0x00000409)                 # PROJECTLCID
    d += _u16(0x0014) + _u32(4) + _u32(0x00000409)                 # PROJECTLCIDINVOKE
    d += _u16(0x0003) + _u32(2) + _u16(0x04E4)                     # PROJECTCODEPAGE: 1252
    d += _u16(0x0004) + _u32(len(name)) + name                    # PROJECTNAME
    d += _u16(0x0005) + _u32(0) + _u16(0x0040) + _u32(0)          # PROJECTDOCSTRING (empty)
    d += _u16(0x0006) + _u32(0) + _u16(0x003D) + _u32(0)          # PROJECTHELPFILEPATH (empty)
    d += _u16(0x0007) + _u32(4) + _u32(0)                         # PROJECTHELPCONTEXT
    d += _u16(0x0008) + _u32(4) + _u32(0)                         # PROJECTLIBFLAGS
    d += _u16(0x0009) + _u32(4) + _u32(1) + _u16(1)               # PROJECTVERSION (reserved, major, minor)
    d += _u16(0x000C) + _u32(0) + _u16(0x003C) + _u32(0)          # PROJECTCONSTANTS (empty)
    # No REFERENCE records: 0x000F both ends the reference array and starts PROJECTMODULES.
    d += _u16(0x000F) + _u32(2) + _u16(1)                         # PROJECTMODULES: one module
    d += _u16(0x0013) + _u32(2) + _u16(0xFFFF)                    # PROJECTCOOKIE
    d += _u16(0x0019) + _u32(len(modname)) + modname             # MODULENAME
    d += _u16(0x001A) + _u32(len(modname)) + modname + _u16(0x0032) + _u32(len(modname_u)) + modname_u  # MODULESTREAMNAME
    d += _u16(0x0031) + _u32(4) + _u32(0)                         # MODULEOFFSET: source at offset 0
    d += _u16(0x0021) + _u32(0)                                   # MODULETYPE: procedural
    d += _u16(0x002B) + _u32(0)                                   # MODULE terminator
    return d


def benign_macro_doc() -> bytes:
    """An OLE2 Word document with one inert VBA module (AutoOpen computing 2 + 2)."""
    return make_ole({
        "WordDocument": b"\x00" * 16,
        "Macros/PROJECT": PROJECT_STREAM.encode("ascii"),
        "Macros/VBA/_VBA_PROJECT": b"\xcc\x61\xff\xff\x00\x00\x00",
        "Macros/VBA/dir": _container(_dir_stream(), b"\x00"),
        f"Macros/VBA/{MODULE_NAME}": _container(SOURCE.encode("ascii"), b" "),
    })


if __name__ == "__main__":  # quick self-check: the real oletools path extracts the source
    import hashlib

    from oletools.olevba import VBA_Parser

    data = benign_macro_doc()
    assert data == benign_macro_doc(), "fixture is not deterministic"
    parser = VBA_Parser("benign.doc", data=data)
    assert parser.detect_vba_macros(), "oletools did not detect the VBA project"
    modules = {filename: code for _, _, filename, code in parser.extract_macros()}
    parser.close()
    code = modules.get("Module1.bas", "")
    assert "Sub AutoOpen()" in code and "Compute = 2 + 2" in code, modules
    print("sha256", hashlib.sha256(data).hexdigest(), "size", len(data))
    print("extracted modules:", list(modules))
