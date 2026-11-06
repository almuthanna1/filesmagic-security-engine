from app.models import Finding, ScannerStatus, Severity, WorkerReport
from evaluation.cases import verdicts


def test_each_scanner_is_judged_on_its_own_findings_and_status():
    report = WorkerReport(
        scanners=[ScannerStatus(name="a", status="completed"), ScannerStatus(name="b", status="completed"),
                  ScannerStatus(name="c", status="failed"), ScannerStatus(name="d", status="not_applicable")],
        findings=[Finding(scanner="b", category="x", severity=Severity.HIGH, description="x", rule_id="R")],
    )
    assert verdicts(report) == {"a": "SAFE", "b": "MALICIOUS", "c": "UNABLE_TO_SCAN", "d": "n/a",
                                "aggregate": "MALICIOUS"}
