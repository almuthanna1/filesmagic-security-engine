"""A reference to an object the PDF does not contain (e.g. a Google Slides export's /Outlines 2 0 R,
whose xref entry is free) is the null object (ISO 32000-1 7.3.10), not a repair, when nothing else in
the file can be that object. Every way the bytes could still hold it keeps the coverage issue."""

import struct

import pytest

from app import engine, worker
from app.decision import classify, decide
from app.models import Verdict
from tests.pdf_fixtures import js_action, make_pdf

REPAIRED = {"PDF_STRUCTURE_REPAIRED", "PDF_CHAIN_PARSER_REPAIRED"}
HIDDEN = "<< /Type /Outlines /A " + js_action() + " >>"  # what the missing object could have carried


def scan(data: bytes):
    report = engine.correlate(worker.analyse(engine.SCANNERS, data))
    applicable = sum(s.status != "not_applicable" for s in report.scanners)
    failed = sum(s.status == "failed" for s in report.scanners)
    verdict = decide(report.findings, applicable, failed, report.coverage_complete)
    _, authorization, _ = classify(verdict, report.scanners, report.coverage_issues, [])
    return verdict, authorization, {i.code for i in report.coverage_issues}, {f.rule_id for f in report.findings}


def dangling(target: int = 5) -> bytes:
    """Catalog /Outlines -> an object that is a free xref entry (5) or beyond /Size (9)."""
    return make_pdf(catalog_extra=f"/Outlines {target} 0 R", objects={6: "<< >>"})


@pytest.mark.parametrize("target", [5, 9])
def test_dangling_reference_in_a_well_formed_file_is_null_not_a_repair(target):
    verdict, authorization, coverage, rules = scan(dangling(target))
    assert (verdict, authorization, coverage) == (Verdict.SAFE, "allow", set())
    assert "PDF_UNDEFINED_REFERENCE" in rules and not rules & REPAIRED


def test_the_corrected_file_is_safe_without_the_note():
    verdict, _, coverage, rules = scan(make_pdf(objects={6: "<< >>"}))
    assert (verdict, coverage) == (Verdict.SAFE, set()) and "PDF_UNDEFINED_REFERENCE" not in rules


def objstm_with_unindexed(escaped: bool = False) -> bytes:
    """Object 5 (the outline with a script) is the only member of an object stream, and the xref stream
    does not index it: only the stream's bytes show that it exists."""
    out = bytearray(make_pdf(catalog_extra="/Outlines 5 0 R", objects={5: HIDDEN}, compressed={5}))
    row = out.rindex(b">>\nstream\n") + len(b">>\nstream\n") + 5 * 7  # xref stream row for object 5
    out[row:row + 7] = struct.pack(">BIH", 0, 0, 0xFFFF)
    if escaped:  # same length, so every offset stays valid
        out = out.replace(b"/Type /ObjStm /N", b"/Type/O#62jStm/N")
    return bytes(out)


@pytest.mark.parametrize("data", [
    dangling() + b"5\x000\x00obj " + HIDDEN.encode() + b" endobj\n",  # NUL is PDF whitespace; pypdf's search misses it
    dangling() + b"5 0 %c\nobj " + HIDDEN.encode() + b" endobj\n",  # a comment inside the header
    dangling() + b"5 1 obj " + HIDDEN.encode() + b" endobj\n",  # another generation
    dangling() + b"(5 0 obj)\n",  # only text, but not provably so: stays conservative
    objstm_with_unindexed(),
    objstm_with_unindexed(escaped=True),
    make_pdf(catalog_extra="/Outlines 5 0 R", objects={6: "<< >>"}, header_offset=500),  # a real repair too
], ids=["nul-header", "comment-header", "other-generation", "obj-in-text", "object-stream", "escaped-object-stream",
        "with-repair"])
def test_bytes_that_could_hold_the_missing_object_keep_the_coverage_issue(data):
    verdict, authorization, coverage, rules = scan(data)  # SUSPICIOUS where another scanner sees the script
    assert verdict in (Verdict.UNABLE_TO_SCAN, Verdict.SUSPICIOUS) and authorization == "consent_required"
    assert coverage >= REPAIRED and "PDF_UNDEFINED_REFERENCE" not in rules


def test_a_dangling_reference_does_not_hide_a_script_elsewhere():
    data = make_pdf(catalog_extra="/Outlines 5 0 R /OpenAction " + js_action(), objects={6: "<< >>"})
    verdict, _, coverage, rules = scan(data)
    assert verdict == Verdict.SUSPICIOUS and coverage == set()
    assert {"PDF_JAVASCRIPT", "ENGINE_PDF_AUTO_CHAIN_SCRIPT"} <= rules


def test_a_present_outline_with_a_script_is_still_found():
    verdict, _, _, rules = scan(make_pdf(catalog_extra="/Outlines 5 0 R", objects={5: HIDDEN}))
    assert verdict == Verdict.SUSPICIOUS and "PDF_JAVASCRIPT" in rules
