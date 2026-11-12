"""ELF structural analysis and detection (custom engine). Inert, in-memory fixtures only; real
benign binaries are checked in Linux CI (tests/test_elf_linux.py).

Design: the bounded parser (app.engine.elf) and structural scanner (app.engine.elf_scan) report
only INFO/LOW, so structure alone never exceeds SUSPICIOUS. A specific malicious indicator from
the engine's YARA rules (app/engine/rules/elf.yar) is HIGH, and correlation lets it stand as
MALICIOUS once the parser confirmed a genuine ELF, replacing the generic Native_Executable.
Unknown executables stay SUSPICIOUS; a malformed ELF fails closed (never SAFE).
"""

import shutil
import sys
from pathlib import Path

import pytest

from app import engine, worker
from app.engine import elf
from app.scanners import yarax
from app.engine.elf_scan import ElfScanner
from app.models import Severity
from app.scanners import SCANNERS as REFERENCE
from evaluation.cases import verdicts
from tests.elf_fixtures import INERT_MARKER, UPX_BANNER, UPX_MAGIC, build_elf


def scan(data: bytes):
    return worker.analyse(REFERENCE, data), engine.correlate(worker.analyse(engine.SCANNERS, data))


def rules(report) -> dict[str, str]:
    return {f.rule_id: f.severity.value for f in report.findings}


correlate_module = sys.modules["app.engine.correlate"]  # the name app.engine.correlate is the function
MARKER_RULE = "ELF_Inert_Marker_Pipeline"
TEST_RULES = Path(__file__).parent / "rules"


def with_test_rules(tmp_path):
    """The unified scanners with the test-only rules compiled beside the production engine rules."""
    for f in [*engine.RULES_DIR.glob("*.yar"), *TEST_RULES.glob("*.yar")]:
        shutil.copy(f, tmp_path / f.name)
    signatures = engine.EngineSignatures(tmp_path)
    assert signatures.ready, signatures.error
    return [signatures if isinstance(s, engine.EngineSignatures) else s for s in engine.SCANNERS]


@pytest.fixture
def validated_scan(tmp_path, monkeypatch):
    """A scan as it will be once a signature is validated: the test-only marker rule loaded and
    listed as validated. Nothing outside this fixture does either."""
    scanners = with_test_rules(tmp_path)
    monkeypatch.setattr(correlate_module, "ELF_SIGNATURE_RULES", {MARKER_RULE})
    return lambda data: engine.correlate(worker.analyse(scanners, data))


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


def test_validated_evidence_with_tampered_upx_is_malicious(validated_scan):
    # MALICIOUS comes from the validated signature; the audit trail keeps the replaced finding.
    uni = validated_scan(build_elf(marker=True, sections=False, extra=UPX_BANNER))
    assert verdicts(uni)["aggregate"] == "MALICIOUS"
    assert rules(uni).get(MARKER_RULE) == "HIGH" and rules(uni).get("ELF_UPX_Tampered_Header") == "MEDIUM"
    assert "Native_Executable" not in rules(uni)
    note = next(f for f in uni.findings if f.rule_id == "ENGINE_CORRELATION")
    assert any(e.startswith("raw yara-x:Native_Executable MEDIUM") for e in note.evidence)


def test_only_validated_rules_can_be_high():
    text = (engine.RULES_DIR / "elf.yar").read_text(encoding="utf-8")
    high = {block.split()[0] for block in text.split("\nrule ")[1:] if 'severity = "HIGH"' in block}
    assert high == correlate_module.ELF_SIGNATURE_RULES == set()  # nothing validated yet


# ---- test-only signatures cannot affect production verdicts ----

def test_no_test_signature_is_production_loadable():
    app_dir = Path(engine.__file__).resolve().parents[1]
    for f in app_dir.rglob("*"):
        if f.is_file() and f.suffix in (".yar", ".py"):
            text = f.read_text(encoding="utf-8")
            assert INERT_MARKER.decode() not in text and MARKER_RULE not in text and "test-marker" not in text, f
    # The production scanners compile only app/rules and app/engine/rules; tests/ is outside both.
    loaded = {Path(yarax.RULES_DIR).resolve(), Path(engine.RULES_DIR).resolve()}
    assert loaded == {app_dir / "rules", app_dir / "engine" / "rules"}
    assert not any(TEST_RULES.resolve().is_relative_to(d) for d in loaded)
    # The production image holds app/ and requirements.txt only (allow-list), so tests/rules is not in it.
    ignore = (app_dir.parent / ".dockerignore").read_text(encoding="utf-8").split("\n")
    assert [line for line in ignore if line.startswith(("*", "!"))][:3] == ["*", "!app/", "!requirements.txt"]


def test_marker_does_not_change_a_production_verdict():
    for with_marker, without in zip(scan(build_elf(marker=True)), scan(build_elf())):
        assert verdicts(with_marker)["aggregate"] == verdicts(without)["aggregate"] == "SUSPICIOUS"
        assert rules(with_marker) == rules(without) and MARKER_RULE not in rules(with_marker)


def test_a_loaded_test_rule_is_still_not_validated_evidence(tmp_path):
    # Even with the test rule compiled in, correlation does not treat it as validated: the original
    # finding stands and nothing is replaced.
    report = engine.correlate(worker.analyse(with_test_rules(tmp_path), build_elf(marker=True)))
    assert rules(report).get("Native_Executable") == "MEDIUM"
    assert not any("specific malicious ELF indicator" in e for f in report.findings for e in f.evidence)


def test_legitimate_upx_is_not_flagged():
    # The UPX! magic is present: a normally packed binary, not the evasion. No false positive.
    _, uni = scan(build_elf(extra=UPX_MAGIC + b"\x00\x00\x00\x00" + UPX_BANNER))
    assert verdicts(uni)["aggregate"] == "SUSPICIOUS"
    assert "ELF_UPX_Tampered_Header" not in rules(uni)


def test_marker_pipeline_validates_correlation(validated_scan):
    uni = validated_scan(build_elf(marker=True))
    assert verdicts(uni)["aggregate"] == "MALICIOUS"
    assert rules(uni).get(MARKER_RULE) == "HIGH"
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
