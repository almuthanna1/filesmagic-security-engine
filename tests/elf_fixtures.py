"""Minimal, inert ELF fixtures built in memory for tests.

These are structurally valid ELF64 objects with no real code: the "text" is a handful of NOPs and
a return, and the "malicious" fixtures carry only an obviously inert marker string
(INERT_MARKER), never real malware bytes. They exercise the parser (app.engine.elf), the engine's
ELF YARA rules and correlation. Real benign binaries (/bin/*) are tested separately in Linux CI
(tests/test_elf_linux.py).
"""

import struct

BASE = 0x400000
TEXT_VADDR = 0x401000
# An inert stand-in for a family signature, matched only by the test-only rule tests/rules/elf_marker.yar.
INERT_MARKER = b"FILESMAGIC-INERT-ELF-MALWARE-MARKER-v1"
# UPX's own benign decompression-stub banner (present in UPX-packed files). Inert: not malware.
UPX_BANNER = b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $"
UPX_MAGIC = b"UPX!"

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
PF_X, PF_W, PF_R = 0x1, 0x2, 0x4
SHT_PROGBITS, SHT_SYMTAB, SHT_STRTAB, SHT_DYNAMIC, SHT_DYNSYM = 1, 2, 3, 6, 11
SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR = 0x1, 0x2, 0x4


def _phdr(p_type, flags, off, vaddr, filesz, memsz):
    return struct.pack("<IIQQQQQQ", p_type, flags, off, vaddr, vaddr, filesz, memsz, 0x1000)


def _shdr(name, s_type, flags, addr, off, size, link=0, entsize=0):
    return struct.pack("<IIQQQQIIQQ", name, s_type, flags, addr, off, size, link, 0, 1, entsize)


def build_elf(*, text=b"\x90\x90\xc3", entry=None, e_type=2, wx=False, interp="/lib64/ld-linux-x86-64.so.2",
              needed=("libc.so.6",), sections=True, stripped=False, extra=b"", marker=False,
              marker_in_load=True, machine=0x3e):
    """A minimal ELF64. Layout: [ehdr][phdrs][interp][text(+marker)][dynamic][dynstr][shstrtab][shdrs][extra].

    wx: add a writable+executable PT_LOAD. sections=False: no section headers (shnum=0).
    stripped: omit .symtab. marker: embed INERT_MARKER (in the loaded text if marker_in_load, else in `extra`).
    """
    entry = TEXT_VADDR if entry is None else entry
    text = text + (INERT_MARKER if marker and marker_in_load else b"")
    tail_marker = INERT_MARKER if marker and not marker_in_load else b""

    ehsize, phentsize, shentsize = 64, 56, 64
    dynstr = b"\x00" + b"\x00".join(n.encode() for n in needed) + b"\x00"
    # Offsets of each needed name inside dynstr.
    pos, needed_off = 1, []
    for n in needed:
        needed_off.append(pos)
        pos += len(n) + 1

    phdrs = []
    phdrs.append(("interp",))  # placeholder; filled after we know offsets
    nph = 2 + (1 if interp else 0) + (1 if wx else 0)  # LOAD + DYNAMIC + optional INTERP + optional WX LOAD

    phoff = ehsize
    cur = phoff + nph * phentsize
    interp_off = cur
    interp_bytes = (interp.encode() + b"\x00") if interp else b""
    cur += len(interp_bytes)
    text_off = cur
    cur += len(text)
    dyn_off = cur

    # Dynamic entries: NEEDED*, STRTAB (vaddr), NULL.
    dynstr_vaddr = BASE + 0  # placed via its own mapping; we expose it through a section below
    dyn_entries = b""
    for o in needed_off:
        dyn_entries += struct.pack("<qQ", 1, o)         # DT_NEEDED
    dynstr_off_placeholder = cur  # dynstr file offset computed next
    dyn_size = (len(needed_off) + 2) * 16
    dynstr_off = dyn_off + dyn_size
    dyn_entries += struct.pack("<qQ", 5, dynstr_off)    # DT_STRTAB -> vaddr == file offset (addr=offset below)
    dyn_entries += struct.pack("<qQ", 0, 0)             # DT_NULL
    cur = dynstr_off + len(dynstr)

    # Section header string table.
    names = ["", ".text", ".dynamic", ".dynstr", ".shstrtab"] + ([] if stripped else [".symtab"])
    shstr = b"\x00"
    name_off = {}
    for n in names[1:]:
        name_off[n] = len(shstr)
        shstr += n.encode() + b"\x00"
    name_off[""] = 0
    shstr_off = cur
    cur += len(shstr)

    symtab_off = cur
    symtab = b"\x00" * 24 if not stripped else b""  # one null Elf64_Sym, enough to be "present"
    cur += len(symtab)

    shoff = cur if sections else 0

    # Program headers now that offsets are known.
    ph = b""
    load_filesz = dyn_off  # first LOAD covers header..text..(dynamic starts new region, but fine for parser)
    ph += _phdr(PT_LOAD, PF_R | PF_X, 0, BASE, cur, cur)
    if interp:
        ph += _phdr(PT_INTERP, PF_R, interp_off, BASE + interp_off, len(interp_bytes), len(interp_bytes))
    ph += _phdr(PT_DYNAMIC, PF_R | PF_W, dyn_off, BASE + dyn_off, dyn_size, dyn_size)
    if wx:
        ph += _phdr(PT_LOAD, PF_R | PF_W | PF_X, text_off, TEXT_VADDR, len(text), len(text))
    assert len(ph) == nph * phentsize, (len(ph), nph * phentsize)

    # Section headers.
    sh = b""
    shnum = 0
    shstrndx = 0
    if sections:
        secs = [
            ("", 0, 0, 0, 0, 0, 0),
            (".text", SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR, TEXT_VADDR, text_off, len(text), 0),
            (".dynamic", SHT_DYNAMIC, SHF_ALLOC | SHF_WRITE, BASE + dyn_off, dyn_off, dyn_size, 3),
            (".dynstr", SHT_STRTAB, SHF_ALLOC, dynstr_off, dynstr_off, len(dynstr), 0),
            (".shstrtab", SHT_STRTAB, 0, 0, shstr_off, len(shstr), 0),
        ]
        if not stripped:
            secs.append((".symtab", SHT_SYMTAB, 0, 0, symtab_off, len(symtab), 0))
        shstrndx = 4
        for nm, st, fl, addr, off, size, link in secs:
            sh += _shdr(name_off[nm], st, fl, addr, off, size, link, 24 if st == SHT_SYMTAB else 0)
        shnum = len(secs)

    ehdr = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr += struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, entry, phoff, shoff, 0,
                        ehsize, phentsize, nph, shentsize, shnum, shstrndx)

    tail_off = shoff + len(sh) if sections else cur  # section-header table lives at shoff
    out = bytearray(tail_off + len(tail_marker) + len(extra))
    out[0:len(ehdr)] = ehdr
    out[phoff:phoff + len(ph)] = ph
    if interp:
        out[interp_off:interp_off + len(interp_bytes)] = interp_bytes
    out[text_off:text_off + len(text)] = text
    out[dyn_off:dyn_off + len(dyn_entries)] = dyn_entries
    out[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    out[shstr_off:shstr_off + len(shstr)] = shstr
    if symtab:
        out[symtab_off:symtab_off + len(symtab)] = symtab
    if sections:
        out[shoff:shoff + len(sh)] = sh
    out[tail_off:tail_off + len(tail_marker)] = tail_marker
    out[tail_off + len(tail_marker):] = extra
    return bytes(out)
