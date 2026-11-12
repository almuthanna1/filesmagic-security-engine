"""Bounded, static ELF structural analysis for the custom engine (standard library only).

No byte of the file is executed. The parser reads the ELF header, the program-header table
(segments), the section-header table (sections), and the dynamic table's needed libraries,
soname and interpreter. Every count, offset and length is bounded and kept inside the file;
anything malformed or over a limit raises ElfScanError, so a broken or hostile file can never
look clean (the worker records a failed scan, never SAFE).

What it does NOT do: follow no relocations, run no code, resolve no symbols beyond names, and
decompress nothing. It is a structural reader, not a loader.

The derived indicators (writable-and-executable load segment, entry point outside executable
sections, missing section headers, stripped) are *weak* on their own: ordinary software trips
some of them. The scanner (app.engine.correlate.ElfScanner) reports them at INFO/LOW only, so
structure alone never raises the verdict above SUSPICIOUS. Strong, family-level evidence comes
from the engine's YARA-X signatures (app/engine/rules/elf.yar); correlation requires this parser
to confirm a genuine, loadable ELF before such a match is allowed to stand as MALICIOUS.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MAGIC = b"\x7fELF"

# Bounds: generous enough for real toolchains, small enough to stop a hostile header.
MAX_SEGMENTS = 1_000
MAX_SECTIONS = 8_000
MAX_DYNAMIC = 20_000
MAX_NAME = 256          # bytes read for one section/library name
MAX_NEEDED = 2_000      # DT_NEEDED entries kept

# e_type
ET_EXEC, ET_DYN = 2, 3
# p_type
PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
# p_flags
PF_X, PF_W = 0x1, 0x2
# sh_type
SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC = 2, 3, 6
# sh_flags
SHF_WRITE, SHF_EXECINSTR = 0x1, 0x4
# d_tag
DT_NULL, DT_NEEDED, DT_STRTAB, DT_SONAME = 0, 1, 5, 14


class ElfScanError(RuntimeError):
    """The file could not be analysed as a trustworthy ELF. The message is safe to return."""


@dataclass
class Segment:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int


@dataclass
class Elf:
    bits: int               # 32 or 64
    little_endian: bool
    e_type: int
    machine: int
    entry: int
    segments: list[Segment] = field(default_factory=list)
    sections: list[Section] = field(default_factory=list)
    interpreter: str | None = None
    needed: list[str] = field(default_factory=list)
    soname: str | None = None

    # ---- derived structural indicators (each weak on its own) ----
    @property
    def wx_segments(self) -> list[Segment]:
        """PT_LOAD segments mapped writable AND executable (W^X violation)."""
        return [s for s in self.segments if s.type == PT_LOAD and s.flags & PF_W and s.flags & PF_X]

    @property
    def has_section_headers(self) -> bool:
        return bool(self.sections)

    @property
    def stripped(self) -> bool:
        """No symbol table section present (common after stripping; also done by packers)."""
        return self.has_section_headers and not any(s.type == SHT_SYMTAB for s in self.sections)

    @property
    def entry_outside_code(self) -> bool:
        """Entry point not inside any allocated executable section. Only meaningful for ET_EXEC/ET_DYN
        with section headers and a non-zero entry; unknown otherwise (returns False, not a signal)."""
        exec_secs = [s for s in self.sections if s.flags & SHF_EXECINSTR and s.size]
        if not exec_secs or not self.entry:
            return False
        return not any(s.addr <= self.entry < s.addr + s.size for s in exec_secs)


def _unpack(fmt: str, data: bytes, off: int) -> tuple:
    size = struct.calcsize(fmt)
    if off < 0 or off + size > len(data):
        raise ElfScanError("ELF structure points outside the file")
    return struct.unpack_from(fmt, data, off)


def _cstr(data: bytes, off: int, limit: int = MAX_NAME) -> str:
    if not 0 <= off < len(data):
        return ""
    end = data.find(b"\x00", off, min(off + limit, len(data)))
    raw = data[off:end if end != -1 else min(off + limit, len(data))]
    return raw.decode("latin-1", "replace")


def parse(data: bytes) -> Elf:
    """Parse `data` as an ELF, bounded. Raises ElfScanError on anything malformed or over a limit."""
    if len(data) < 16 or data[:4] != MAGIC:
        raise ElfScanError("not an ELF file")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ElfScanError("ELF identifies neither a 32- nor 64-bit, little- nor big-endian object")
    bits = 32 if ei_class == 1 else 64
    le = ei_data == 1
    e = "<" if le else ">"
    word = "I" if bits == 32 else "Q"

    # Header
    hdr = f"{e}HHI{word}{word}{word}IHHHHHH"
    if len(data) < 16 + struct.calcsize(hdr):
        raise ElfScanError("ELF header is truncated")
    (e_type, machine, _ver, entry, phoff, shoff, _flags, _ehsize,
     phentsize, phnum, shentsize, shnum, shstrndx) = _unpack(hdr, data, 16)

    elf = Elf(bits=bits, little_endian=le, e_type=e_type, machine=machine, entry=entry)

    # Program headers (segments)
    if phnum:
        if phnum > MAX_SEGMENTS:
            raise ElfScanError(f"ELF declares {phnum} segments (limit {MAX_SEGMENTS})")
        exp = 32 if bits == 32 else 56
        if phentsize != exp:
            raise ElfScanError(f"ELF program-header entry size {phentsize} is not {exp}")
        for i in range(phnum):
            off = phoff + i * phentsize
            if bits == 64:
                p_type, p_flags, p_off, p_vaddr, _p_paddr, p_filesz, p_memsz, _al = _unpack(f"{e}IIQQQQQQ", data, off)
            else:
                p_type, p_off, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, _al = _unpack(f"{e}IIIIIIII", data, off)
            elf.segments.append(Segment(p_type, p_flags, p_off, p_vaddr, p_filesz, p_memsz))

    # Section headers
    if shnum:
        if shnum > MAX_SECTIONS:
            raise ElfScanError(f"ELF declares {shnum} sections (limit {MAX_SECTIONS})")
        exp = 40 if bits == 32 else 64
        if shentsize != exp:
            raise ElfScanError(f"ELF section-header entry size {shentsize} is not {exp}")
        raw = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if bits == 64:
                sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, *_ = _unpack(f"{e}IIQQQQIIQQ", data, off)
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size, *_ = _unpack(f"{e}IIIIIIIIII", data, off)
            raw.append((sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size))
        # Resolve names from the section-header string table (bounded; bad index -> empty names).
        str_off = None
        if shstrndx < len(raw):
            str_off = raw[shstrndx][4]
        for sh_name, sh_type, sh_flags, sh_addr, sh_off, sh_size in raw:
            name = _cstr(data, str_off + sh_name, MAX_NAME) if str_off is not None else ""
            elf.sections.append(Section(name, sh_type, sh_flags, sh_addr, sh_off, sh_size))

    _read_interp(elf, data)
    _read_dynamic(elf, data)
    return elf


def _read_interp(elf: Elf, data: bytes) -> None:
    for s in elf.segments:
        if s.type == PT_INTERP and s.filesz:
            elf.interpreter = _cstr(data, s.offset, min(s.filesz, MAX_NAME))
            return


def _read_dynamic(elf: Elf, data: bytes) -> None:
    """Needed libraries and soname from the .dynamic section and its linked string table.

    Section-based only: the string table is the section whose sh_link the dynamic section names,
    so no virtual-address-to-offset mapping is needed. Packed objects with no section headers
    yield no library list (itself a weak indicator), never a crash."""
    dyn = next((s for s in elf.sections if s.type == SHT_DYNAMIC), None)
    if dyn is None or not dyn.size:
        return
    ent = 8 if elf.bits == 32 else 16
    count = min(dyn.size // ent, MAX_DYNAMIC)
    e = "<" if elf.little_endian else ">"
    word = "i" if elf.bits == 32 else "q"
    needed_offsets, strtab_vaddr, soname_off = [], None, None
    for i in range(count):
        tag, val = _unpack(f"{e}{word}{'I' if elf.bits == 32 else 'Q'}", data, dyn.offset + i * ent)
        if tag == DT_NULL:
            break
        if tag == DT_NEEDED and len(needed_offsets) < MAX_NEEDED:
            needed_offsets.append(val)
        elif tag == DT_STRTAB:
            strtab_vaddr = val
        elif tag == DT_SONAME:
            soname_off = val
    if strtab_vaddr is None:
        return
    # Map the string table's virtual address to a file offset through the section that contains it
    # (file_offset = vaddr + base, where base = section.offset - section.addr).
    base = next((s.offset - s.addr for s in elf.sections
                 if s.addr and s.addr <= strtab_vaddr < s.addr + s.size), None)
    if base is None:
        return
    strtab_file = strtab_vaddr + base
    for o in needed_offsets:
        if name := _cstr(data, strtab_file + o, MAX_NAME):
            elf.needed.append(name)
    if soname_off is not None:
        elf.soname = _cstr(data, strtab_file + soname_off, MAX_NAME) or None


def summary(elf: Elf) -> dict:
    """Small, loggable description (no file bytes)."""
    return {
        "bits": elf.bits, "endian": "le" if elf.little_endian else "be", "type": elf.e_type,
        "machine": elf.machine, "segments": len(elf.segments), "sections": len(elf.sections),
        "interpreter": elf.interpreter, "needed": elf.needed[:20], "soname": elf.soname,
        "wx_segments": len(elf.wx_segments), "stripped": elf.stripped,
        "entry_outside_code": elf.entry_outside_code, "has_section_headers": elf.has_section_headers,
    }
