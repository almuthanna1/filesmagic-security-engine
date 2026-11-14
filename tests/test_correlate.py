import asyncio

import pytest

from app import engine, worker
from app.decision import decide
from app.models import Finding, ScannerStatus, Severity, Verdict, WorkerReport
from evaluation.cases import CLICK_LINK_JS, cases, verdicts
from tests.pdf_fixtures import make_pdf

CASE = {c["id"]: c["data"] for c in cases()}


def unified(data: bytes) -> WorkerReport:
    return engine.correlate(worker.analyse(engine.SCANNERS, data))


def rules(report: WorkerReport) -> set[str]:
    return {f.rule_id for f in report.findings}


@pytest.mark.parametrize("case, verdict, present, absent", [
    ("1-pdf-clean", "SAFE", set(), {"ENGINE_CORRELATION"}),
    ("2-pdf-form-keystroke-js", "SUSPICIOUS", {"PDF_JAVASCRIPT", "ENGINE_PDF_USER_TRIGGERED_SCRIPT"},
     {"PDF_JavaScript_With_Automatic_Action", "ENGINE_PDF_JavaScript_With_Automatic_Trigger"}),
    # Issue 1: the page destination made the click-only script "automatic" in the reference engine.
    ("2b-pdf-open-at-page-click-js", "SUSPICIOUS", {"PDF_JAVASCRIPT", "ENGINE_PDF_USER_TRIGGERED_SCRIPT"},
     {"PDF_AUTO_JAVASCRIPT", "ENGINE_PDF_AUTO_CHAIN_SCRIPT", "PDF_JavaScript_With_Automatic_Action",
      "ENGINE_PDF_JavaScript_With_Automatic_Trigger"}),
    # Over-correction guard: the page's own open trigger stays automatic.
    ("2c-pdf-open-at-page-page-open-js", "SUSPICIOUS",
     {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "ENGINE_PDF_JavaScript_With_Automatic_Trigger"},
     {"PDF_JavaScript_With_Automatic_Action", "ENGINE_PDF_USER_TRIGGERED_SCRIPT"}),
    ("3-pdf-escaped-openaction-js", "SUSPICIOUS", {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"},
     {"PDF_AUTO_JAVASCRIPT"}),
    # The reference engine says MALICIOUS here: an automatic script plus an attachment it never uses.
    # The two LOW attachment findings (PDF scanner, YARA-X) are one attachment: merged, still LOW.
    ("5a-pdf-auto-js-unrelated-attachment", "SUSPICIOUS", {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "ENGINE_PDF_ATTACHMENTS_UNVERIFIED"},
     {"PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD", "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT", "PDF_EMBEDDED_FILE"}),
    ("5b-pdf-auto-js-exports-attachment", "MALICIOUS", {"ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT"},
     {"PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD", "ENGINE_PDF_AUTO_CHAIN_SCRIPT"}),
    # The reference AUTOLOAD stays; the activation graph adds that no loaded part references it.
    ("6b-docx-external-template", "SUSPICIOUS", {"OFFICE_EXTERNAL_AUTOLOAD", "ENGINE_OFFICE_EXTERNAL_NOT_ACTIVATED"},
     {"ENGINE_OFFICE_EXTERNAL_ON_OPEN"}),
])
def test_unified_verdicts_and_evidence(case, verdict, present, absent):
    report = unified(CASE[case])
    assert verdicts(report)["aggregate"] == verdict
    assert present <= rules(report) and not absent & rules(report)


def test_an_unconfirmed_byte_signature_is_kept_and_annotated():
    # An indirect /OpenAction cannot be shown to be a destination from bytes, so the refined rule
    # still fires; the chain view finds no automatic script, so the match is marked unconfirmed.
    report = unified(make_pdf(catalog_extra="/OpenAction 6 0 R", page_extra="/Annots [5 0 R]",
                              objects={5: CLICK_LINK_JS, 6: "[3 0 R /Fit]"}))
    assert "ENGINE_PDF_JavaScript_With_Automatic_Trigger" in rules(report)
    note = next(f for f in report.findings if f.rule_id == "ENGINE_CORRELATION")
    assert note.severity == Severity.INFO and "not confirmed" in note.description


def test_an_automatic_launch_is_high():
    report = unified(make_pdf(catalog_extra="/OpenAction << /S /Launch /F (calc.exe) >>"))
    launch = next(f for f in report.findings if f.rule_id == "ENGINE_PDF_AUTO_CHAIN_LAUNCH")
    assert launch.severity == Severity.HIGH and "calc.exe" in launch.description


def test_custom_c1_coverage_limit_blocks_an_otherwise_safe_unified_result():
    report = WorkerReport(
        scanners=[ScannerStatus(name="custom", status="completed")],
        findings=[Finding(scanner="custom", category="pdf-coverage", severity=Severity.INFO,
                          description="x", rule_id="CUSTOM_PDF_COVERAGE_LIMITED")],
    )
    correlated = engine.correlate(report)
    assert not correlated.coverage_complete
    assert {(issue.scanner, issue.code) for issue in correlated.coverage_issues} == {
        ("custom", "CUSTOM_PDF_C1_COVERAGE_INCOMPLETE")}
    assert decide(correlated.findings, scanners_run=1, coverage_complete=correlated.coverage_complete) == Verdict.UNABLE_TO_SCAN


def reference_report(chain_status: str, chain_findings: list[Finding] = ()) -> WorkerReport:
    auto = Finding(scanner="pdf", category="pdf-javascript", severity=Severity.HIGH, description="x",
                   rule_id="PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD")
    return WorkerReport(scanners=[ScannerStatus(name="pdf", status="completed"),
                                  ScannerStatus(name="pdf-chains", status=chain_status)],
                        findings=[auto, *chain_findings])


@pytest.mark.parametrize("report", [
    reference_report("failed"),
    reference_report("completed", [Finding(scanner="pdf-chains", category="pdf-action-chain", severity=Severity.INFO,
                                           description="x", rule_id="ENGINE_PDF_CHAINS_REPAIRED")]),
])
def test_reference_findings_stand_when_the_chain_view_is_not_unambiguous(report):
    correlated = engine.correlate(report)
    assert "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD" in rules(correlated)
    if any(f.rule_id == "ENGINE_PDF_CHAINS_REPAIRED" for f in report.findings):
        assert not correlated.coverage_complete
        assert {i.code for i in correlated.coverage_issues} == {"PDF_CHAIN_PARSER_REPAIRED"}
    else:
        assert correlated == report


def test_the_worker_runs_the_unified_engine_only_when_asked():
    data = CASE["5a-pdf-auto-js-unrelated-attachment"]
    reference = asyncio.run(worker.run(data))
    candidate = asyncio.run(worker.run(data, worker.command() + ["--engine=unified"]))
    assert [s.name for s in reference.scanners] == ["yara-x", "office", "pdf", "custom"]
    assert [s.name for s in candidate.scanners] == ["yara-x", "office", "pdf", "custom", "yara-x-engine", "pdf-chains", "pdf-integrity", "vba-chains", "ooxml-links", "word-fields"]
    assert (verdicts(reference)["aggregate"], verdicts(candidate)["aggregate"]) == ("MALICIOUS", "SUSPICIOUS")
