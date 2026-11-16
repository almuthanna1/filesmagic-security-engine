"""ENGINE_PDF_NO_ATTACHMENTS: the reference YARA-X rule PDF_Embedded_File matches the bytes
"/EmbeddedFile", which begin the key /EmbeddedFiles of an empty name tree as well as an attachment.
The unified engine lowers that match only when a complete reading proves there is no attachment and
explains every match; anything less keeps it (docs/pdf-accuracy-preregistration.md). Inert fixtures."""

import pytest

from app import engine, worker
from app.engine.correlate import ACCOUNTS, correlate
from app.engine.correlate import finding as engine_finding
from app.models import Finding, ScannerStatus, Severity, WorkerReport
from app.scanners import SCANNERS
from evaluation.cases import verdicts
from evaluation.pdf_accuracy import REQUIRED, synthetic
from tests.pdf_fixtures import make_pdf

SAMPLES = {s["id"]: s for s in synthetic()}
SIGNATURE, RULE = "PDF_Embedded_File", "ENGINE_PDF_NO_ATTACHMENTS"
ORDER = ["SAFE", "SUSPICIOUS", "MALICIOUS"]


def scan(data: bytes):
    return worker.analyse(SCANNERS, data), engine.correlate(worker.analyse(engine.SCANNERS, data))


def rules(report) -> dict[str, str]:
    return {f.rule_id: f.severity.value for f in report.findings}


@pytest.mark.parametrize("sid", [s for s in SAMPLES if SAMPLES[s]["cls"] == "no-attachment" and s != "S04-empty-tree-object-stream"])
def test_an_empty_name_tree_is_not_an_attachment(sid):
    reference, unified = scan(SAMPLES[sid]["data"])
    assert verdicts(reference)["aggregate"] == "SUSPICIOUS" and rules(reference) == {SIGNATURE: "LOW"}
    assert verdicts(unified)["aggregate"] == "SAFE" and SIGNATURE not in rules(unified) and rules(unified)[RULE] == "INFO"
    proof = next(f for f in unified.findings if f.rule_id == RULE).evidence
    assert proof[0].startswith("byte ") and "an empty name tree" in proof[0] and proof[-1] == ACCOUNTS.format("yara-x", SIGNATURE)
    # The removed finding is kept, as it was, in the audit trail.
    note = next(f for f in unified.findings if f.rule_id == "ENGINE_CORRELATION")
    assert f"raw yara-x:{SIGNATURE} LOW: PDF carries an embedded file attachment." in note.evidence


@pytest.mark.parametrize("sid", SAMPLES)
def test_every_synthetic_sample_meets_its_required_outcome(sid):
    sample = SAMPLES[sid]
    reference, unified = scan(sample["data"])
    verdict, need = verdicts(unified)["aggregate"], REQUIRED[sample["cls"]]
    assert verdict == need if sample["cls"] in ("no-attachment", "dangerous") else ORDER.index(verdict) >= ORDER.index(need)
    if sample["cls"] != "no-attachment":  # the change lowers nothing here: no HIGH lost, every warning kept
        high = lambda r: {f.rule_id for f in r.findings if f.severity in (Severity.HIGH, Severity.CRITICAL)}  # noqa: E731
        assert high(reference) <= high(unified) | {"PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD"}  # replaced by the chain rule
        if sample["cls"] != "dangerous":
            assert SIGNATURE in rules(unified) or "ENGINE_PDF_ATTACHMENTS_UNVERIFIED" in rules(unified)


@pytest.mark.parametrize("catalog, objects", [
    ("/Names << /EmbeddedFiles << /Kids [] >> >>", {}),  # /Kids: not shown empty
    ("/Names << /EmbeddedFiles << /Names [(f) null] >> >>", {}),  # names an entry
    ("/Names << /EmbeddedFiles << /Names null >> >>", {}),
    ("/Names << /EmbeddedFilesX << >> >>", {}),  # another name that starts with the bytes
    ("/Names << /EmbeddedFiles 5 0 R >>", {5: "[]"}),  # not a dictionary
    ("/Names << /EmbeddedFiles << >> >> /Info (/EmbeddedFiles )", {}),  # one key, two matches
])
def test_a_match_not_shown_to_be_an_empty_trees_key_is_kept(catalog, objects):
    _, unified = scan(make_pdf(catalog_extra=catalog, objects=objects))
    assert rules(unified).get(SIGNATURE) == "LOW" and RULE not in rules(unified)


def test_several_empty_trees_are_each_explained():
    data = make_pdf(catalog_extra="/Names << /EmbeddedFiles << >> >>", objects={5: "<< /EmbeddedFiles << /Names [] >> >>"})
    _, unified = scan(data)
    assert verdicts(unified)["aggregate"] == "SAFE"
    assert len([e for e in next(f for f in unified.findings if f.rule_id == RULE).evidence if e.startswith("byte ")]) == 2


def report(pdf_status: str = "completed", pdf_rule: str | None = None, severity: Severity = Severity.LOW) -> WorkerReport:
    proof = engine_finding(RULE, Severity.INFO, "x", evidence=["byte 9: ...", ACCOUNTS.format("yara-x", SIGNATURE)])
    match = Finding(scanner="yara-x", category="pdf-embedded-file", severity=severity, description="x", rule_id=SIGNATURE)
    extra = [Finding(scanner="pdf", category="pdf", severity=Severity.LOW, description="x", rule_id=pdf_rule)] if pdf_rule else []
    return WorkerReport(scanners=[ScannerStatus(name=n, status=s) for n, s in
                                  (("yara-x", "completed"), ("pdf", pdf_status), ("pdf-chains", "completed"))],
                        findings=[match, proof, *extra])


def test_the_pdf_scanner_must_agree():
    assert SIGNATURE not in rules(correlate(report()))
    for kept in (report("failed"), report(pdf_rule="PDF_EMBEDDED_FILE"), report(pdf_rule="PDF_STRUCTURE_REPAIRED"),
                 report(pdf_rule="PDF_EMBEDDED_EXECUTABLE"), report(severity=Severity.MEDIUM)):  # above its ceiling
        assert rules(correlate(kept))[SIGNATURE] == kept.findings[0].severity.value
