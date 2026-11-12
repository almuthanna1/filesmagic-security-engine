"""ELF structural analysis and detection (custom engine). Inert, in-memory fixtures only; real
benign binaries are checked in Linux CI (tests/test_elf_linux.py).

Design: the bounded parser (app.engine.elf) and structural scanner (app.engine.elf_scan) report
only INFO/LOW, so structure alone never exceeds SUSPICIOUS. A specific malicious indicator from
the engine's YARA rules (app/engine/rules/elf.yar) is HIGH, and correlation lets it stand as
MALICIOUS once the parser confirmed a genuine ELF, replacing the generic Native_Executable.
Unknown executables stay SUSPICIOUS; a malformed ELF fails closed (never SAFE).
"""

import pytest

from app import engine, worker
from app.engine import elf
from app.engine.elf_scan import ElfScanner
from app.models import Severity
from app.scanners import SCANNERS as REFERENCE
from evaluation.cases import verdicts
from tests.elf_fixtures import INERT_MARKER, UPX_BANNER, UPX_MAGIC, build_elf


def scan(data: bytes):
    return worker.analyse(REFERENCE, data), engine.correlate(worker.analyse(engine.SCANNERS, data))


def rules(report) -> dict[str, str]:
    return {f.rule_id: f.severity.value for f in report.findings}


# ---- parser ----

def test_parser_reads_structure():
    e = elf.parse(build_elf(needed=("libc.so.6", "libpthread.so.0")))
    assert e.bits == 64 and e.little_endian and e.e_type == elf.ET_EXEC
    assert e.interpreter == "/lib64/ld-linux-x86-64.so.2"
    assert e.needed == ["libc.so.6", "libpthread.so.0"]
    assert not e.wx_segments and not e.stripped and not e.entry_outside_code and e.has_section_headers


@pytest.mark.parametrize("kwargs,attr,expected", [
    (dict(wx=True), "wx_segments", True),
    (dict(), "wx_segments", False),
    (dict(stripped=True), "stripped", True),
    (dict(), "stripped", False),
    (dict(sections=False), "has_section_headers", False),
    (dict(entry=0x409999), "entry_outside_code", True),
    (dict(), "entry_outside_code", False),
])
def test_parser_indicators(kwargs, attr, expected):
    value = getattr(elf.parse(build_elf(**kwargs)), attr)
    assert bool(value) == expected


@pytest.mark.parametrize("bad", [b"", b"\x7fELF", b"MZ\x90\x00", b"\x7fELF" + b"\x00" * 300,
                                 bytes(build_elf())[:100]])
def test_parser_rejects_malformed(bad):
    with pytest.raises(elf.ElfScanError):
        elf.parse(bad)


def test_parser_is_bounded():
    # A header claiming a vast number of segments is rejected, not allocated.
    data = bytearray(build_elf())
    data[56:58] = (9999).to_bytes(2, "little")  # e_phnum in the ELF64 header
    with pytest.raises(elf.ElfScanError):
        elf.parse(bytes(data))


# ---- scanner ----

def test_scanner_skips_non_elf():
    assert ElfScanner().scan("x", b"%PDF-1.7\n") is None


def test_scanner_findings_are_info_or_low():
    for kwargs in (dict(), dict(wx=True), dict(stripped=True), dict(sections=False), dict(entry=0x409999)):
        findings = ElfScanner().scan("x", build_elf(**kwargs))
        assert findings and all(f.severity in (Severity.INFO, Severity.LOW) for f in findings)
        assert any(f.rule_id == "ENGINE_ELF_STRUCTURE" for f in findings)


def test_scanner_raises_on_malformed():
    from app.engine.elf_scan import ElfScanError
    with pytest.raises(ElfScanError):
        ElfScanner().scan("x", bytes(build_elf())[:100])


# ---- end-to-end verdicts ----

def test_benign_elf_is_suspicious_in_both_engines():
    ref, uni = scan(build_elf())
    assert verdicts(ref)["aggregate"] == "SUSPICIOUS"
    assert verdicts(uni)["aggregate"] == "SUSPICIOUS"  # unknown executable stays SUSPICIOUS, never SAFE
    assert "Native_Executable" in rules(ref)


@pytest.mark.parametrize("kwargs", [dict(wx=True), dict(stripped=True), dict(sections=False), dict(entry=0x409999)])
def test_structural_indicators_do_not_escalate(kwargs):
    _, uni = scan(build_elf(**kwargs))
    assert verdicts(uni)["aggregate"] == "SUSPICIOUS"
    assert not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in uni.findings)


@pytest.mark.parametrize("kwargs", [dict(sections=False), dict(), dict(wx=True, stripped=True, entry=0x409999)])
def test_tampered_upx_alone_is_suspicious_never_malicious(kwargs):
    # A modified UPX header, even with every structural anomaly, is not validated malicious evidence.
    ref, uni = scan(build_elf(extra=UPX_BANNER, **kwargs))
    assert verdicts(ref)["aggregate"] == "SUSPICIOUS"           # reference engine unchanged
    assert verdicts(uni)["aggregate"] == "SUSPICIOUS"
    assert rules(uni).get("ELF_UPX_Tampered_Header") == "MEDIUM"
    assert not any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in uni.findings)
    assert rules(uni).get("Native_Executable") == "MEDIUM"      # the original finding stands
    note = next(f for f in uni.findings if f.rule_id == "ENGINE_CORRELATION")
    assert any("kept as suspicious only" in e for e in note.evidence)


def test_validated_evidence_with_tampered_upx_is_malicious():
    # MALICIOUS comes from the validated signature; the audit trail keeps the replaced finding.
    _, uni = scan(build_elf(marker=True, sections=False, extra=UPX_BANNER))
    assert verdicts(uni)["aggregate"] == "MALICIOUS"
    assert rules(uni).get("ELF_Inert_Marker_Pipeline") == "HIGH" and rules(uni).get("ELF_UPX_Tampered_Header") == "MEDIUM"
    assert "Native_Executable" not in rules(uni)
    note = next(f for f in uni.findings if f.rule_id == "ENGINE_CORRELATION")
    assert any(e.startswith("raw yara-x:Native_Executable MEDIUM") for e in note.evidence)


def test_only_validated_rules_can_be_high():
    from app.engine import RULES_DIR
    from app.engine.correlate import ELF_SIGNATURE_RULES
    text = (RULES_DIR / "elf.yar").read_text(encoding="utf-8")
    high = {block.split()[0] for block in text.split("\nrule ")[1:] if 'severity = "HIGH"' in block}
    assert high == ELF_SIGNATURE_RULES


def test_legitimate_upx_is_not_flagged():
    # The UPX! magic is present: a normally packed binary, not the evasion. No false positive.
    _, uni = scan(build_elf(extra=UPX_MAGIC + b"\x00\x00\x00\x00" + UPX_BANNER))
    assert verdicts(uni)["aggregate"] == "SUSPICIOUS"
    assert "ELF_UPX_Tampered_Header" not in rules(uni)


def test_marker_pipeline_validates_correlation():
    _, uni = scan(build_elf(marker=True))
    assert verdicts(uni)["aggregate"] == "MALICIOUS"
    assert rules(uni).get("ELF_Inert_Marker_Pipeline") == "HIGH"
    assert INERT_MARKER.decode() not in "".join(f.description for f in uni.findings)  # marker text not echoed


def test_malformed_elf_fails_closed():
    _, uni = scan(bytes(build_elf())[:120])
    assert verdicts(uni)["aggregate"] != "SAFE"
    status = {s.name: s.status for s in uni.scanners}
    assert status["elf-structure"] == "failed"


def test_reference_engine_has_no_elf_scanners():
    ref, _ = scan(build_elf(marker=True))
    names = {f.scanner for f in ref.findings}
    assert "elf-structure" not in names and "yara-x-engine" not in names
    assert verdicts(ref)["aggregate"] == "SUSPICIOUS"  # marker never makes the reference engine MALICIOUS
