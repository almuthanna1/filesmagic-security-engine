import asyncio

import pytest

from app import engine, worker
from app.models import Finding, ScannerStatus, Severity, WorkerReport
from evaluation.cases import cases, verdicts
from tests.pdf_fixtures import make_pdf

CASE = {c["id"]: c["data"] for c in cases()}


def unified(data: bytes) -> WorkerReport:
    return engine.correlate(worker.analyse(engine.SCANNERS, data))


def rules(report: WorkerReport) -> set[str]:
    return {f.rule_id for f in report.findings}


@pytest.mark.parametrize("case, verdict, present, absent", [
    ("1-pdf-clean", "SAFE", set(), {"ENGINE_CORRELATION"}),
    ("2b-pdf-open-at-page-click-js", "SUSPICIOUS", {"PDF_JAVASCRIPT", "ENGINE_CORRELATION"},
     {"PDF_AUTO_JAVASCRIPT", "ENGINE_PDF_AUTO_CHAIN_SCRIPT"}),
    ("3-pdf-escaped-openaction-js", "SUSPICIOUS", {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME"},
     {"PDF_AUTO_JAVASCRIPT"}),
    # The reference engine says MALICIOUS here: an automatic script plus an attachment it never uses.
    ("5a-pdf-auto-js-unrelated-attachment", "SUSPICIOUS", {"ENGINE_PDF_AUTO_CHAIN_SCRIPT", "PDF_EMBEDDED_FILE"},
     {"PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD", "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT"}),
    ("5b-pdf-auto-js-exports-attachment", "MALICIOUS", {"ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT"},
     {"PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD", "ENGINE_PDF_AUTO_CHAIN_SCRIPT"}),
    ("6b-docx-external-template", "SUSPICIOUS", {"OFFICE_EXTERNAL_AUTOLOAD"}, {"ENGINE_CORRELATION"}),
])
def test_unified_verdicts_and_evidence(case, verdict, present, absent):
    report = unified(CASE[case])
    assert verdicts(report)["aggregate"] == verdict
    assert present <= rules(report) and not absent & rules(report)


def test_an_unconfirmed_byte_signature_is_kept_and_annotated():
    report = unified(CASE["2-pdf-form-keystroke-js"])
    assert "PDF_JavaScript_With_Automatic_Action" in rules(report)
    note = next(f for f in report.findings if f.rule_id == "ENGINE_CORRELATION")
    assert note.severity == Severity.INFO and "not confirmed" in note.description


def test_an_automatic_launch_is_high():
    report = unified(make_pdf(catalog_extra="/OpenAction << /S /Launch /F (calc.exe) >>"))
    launch = next(f for f in report.findings if f.rule_id == "ENGINE_PDF_AUTO_CHAIN_LAUNCH")
    assert launch.severity == Severity.HIGH and "calc.exe" in launch.description


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
    assert engine.correlate(report) == report


def test_the_worker_runs_the_unified_engine_only_when_asked():
    data = CASE["5a-pdf-auto-js-unrelated-attachment"]
    reference = asyncio.run(worker.run(data))
    candidate = asyncio.run(worker.run(data, worker.command() + ["--engine=unified"]))
    assert [s.name for s in reference.scanners] == ["yara-x", "office", "pdf", "custom"]
    assert [s.name for s in candidate.scanners] == ["yara-x", "office", "pdf", "custom", "pdf-chains"]
    assert (verdicts(reference)["aggregate"], verdicts(candidate)["aggregate"]) == ("MALICIOUS", "SUSPICIOUS")
