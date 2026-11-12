"""ElfScanner: bounded structural findings for ELF files (custom engine).

Parses with app.engine.elf (standard library, no execution) and reports what it found. Every
finding here is INFO or LOW: ordinary software trips these indicators, so structure alone never
raises the verdict above SUSPICIOUS. They corroborate and explain a family/evasion signature
match (app/engine/rules/elf.yar) that correlation may let stand as MALICIOUS; on their own they
are context for an analyst.

A file that is not an ELF returns None (not handled). An ELF that cannot be parsed raises
ElfScanError, so the worker records a failed scan and the file can never come back SAFE on the
strength of this scanner; the reference Native_Executable rule still marks it SUSPICIOUS.
"""

import struct

from app.engine import elf
from app.models import Finding, Severity
from app.scanners.base import ScanError

NAME = "elf-structure"


class ElfScanError(ScanError):
    malformed_causes = (struct.error,)


def _finding(rule: str, severity: Severity, description: str, evidence: list[str] = ()) -> Finding:
    return Finding(scanner=NAME, category="elf-structure", severity=severity, rule_id=rule,
                   description=description, evidence=[e[:500] for e in list(evidence)[:50]])


def findings(parsed: elf.Elf) -> list[Finding]:
    s = elf.summary(parsed)
    kind = {elf.ET_EXEC: "executable", elf.ET_DYN: "shared object or PIE"}.get(parsed.e_type, f"type {parsed.e_type}")
    out = [_finding(
        "ENGINE_ELF_STRUCTURE", Severity.INFO,
        f"ELF {parsed.bits}-bit {'little' if parsed.little_endian else 'big'}-endian {kind}, machine {parsed.machine}, "
        f"{len(parsed.segments)} segment(s), {len(parsed.sections)} section(s).",
        evidence=[f"interpreter: {parsed.interpreter}"] if parsed.interpreter else [])]
    if parsed.needed:
        out[0].evidence.append(f"needed: {', '.join(parsed.needed[:20])}")
    if parsed.soname:
        out[0].evidence.append(f"soname: {parsed.soname}")

    if wx := parsed.wx_segments:
        out.append(_finding(
            "ENGINE_ELF_WRITABLE_EXECUTABLE_SEGMENT", Severity.LOW,
            f"{len(wx)} loadable segment(s) are mapped writable and executable (W^X violation), which self-modifying "
            "or unpacking code needs and ordinary compilers avoid. On its own this is not proof of malice.",
            evidence=[f"segment vaddr 0x{s.vaddr:x} filesz {s.filesz} flags rwx" for s in wx]))
    if parsed.entry_outside_code:
        out.append(_finding(
            "ENGINE_ELF_ENTRY_OUTSIDE_CODE", Severity.LOW,
            f"The entry point 0x{parsed.entry:x} is not inside any executable section, as seen when a loader stub or "
            "unpacker runs before the real code. Not conclusive by itself."))
    if not parsed.has_section_headers:
        out.append(_finding(
            "ENGINE_ELF_NO_SECTION_HEADERS", Severity.INFO,
            "The ELF has no section headers. Packers and some size-optimised builds strip them; many ordinary "
            "binaries keep them."))
    elif parsed.stripped:
        out.append(_finding(
            "ENGINE_ELF_STRIPPED", Severity.INFO,
            "The ELF has section headers but no symbol table (stripped). Common in release builds and in packed malware."))
    return out


class ElfScanner:
    name = NAME

    def scan(self, filename: str, data: bytes) -> list[Finding] | None:
        if data[:4] != elf.MAGIC:
            return None
        try:
            parsed = elf.parse(data)
        except elf.ElfScanError as e:
            raise ElfScanError(str(e)) from None  # no __cause__ -> classified invalid_structure
        except Exception as e:
            raise ElfScanError(f"ELF analysis failed: {type(e).__name__}") from e
        return findings(parsed)
