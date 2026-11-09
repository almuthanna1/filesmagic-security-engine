"""The offline-validation driver refuses to produce evidence unless every gate holds, and reports
every difference from the Windows evidence."""

from evaluation import offline_validation as ov

GOOD = {"host_network": {"offline": True}, "engine_commit": "a" * 40, "working_tree_dirty": False,
        "dependency_drift": [], "strict_isolation_configured": True, "confinement": ov.CONFINEMENT}


def test_all_gates_hold():
    assert ov.gates(GOOD, "a" * 40, []) == []


def test_each_missing_control_aborts():
    for change in ({"host_network": {"offline": False}}, {"engine_commit": "b" * 40}, {"working_tree_dirty": True},
                   {"dependency_drift": ["pypdf: required 6.19.0, installed 6.0.0"]},
                   {"strict_isolation_configured": False}, {"confinement": "unconfined"},
                   {"confinement": "filesmagic-eval-python (complain)"}, {"confinement": None}):
        assert ov.gates(GOOD | change, "a" * 40, []), change
    assert ov.gates(GOOD, "a" * 40, ["x.pdf does not match its manifest SHA-256"])


def result(set_, id_, engine, verdict, *findings, missing=(), status=None):
    return {"set": set_, "id": id_, "engine": engine, "verdicts": {"aggregate": verdict},
            "isolation_missing": list(missing), "status": status or {},
            "findings": [dict(zip(("scanner", "rule_id", "severity"), f.split(":"))) for f in findings]}


def test_differences_from_the_windows_evidence_are_listed():
    expected = {("corpus", "a.pdf", "unified"): ("SAFE", ["pdf-chains:ENGINE_PDF_ATTACHMENTS_VERIFIED:INFO"])}
    same, changed, extra = ov.compare([
        result("corpus", "a.pdf", "unified", "SAFE", "pdf-chains:ENGINE_PDF_ATTACHMENTS_VERIFIED:INFO"),
        result("corpus", "a.pdf", "unified", "SUSPICIOUS", "pdf:PDF_EMBEDDED_FILE:LOW"),
        result("corpus", "new.pdf", "unified", "SAFE")], expected)
    assert same["same"] and not changed["same"] and not extra["same"]
    assert changed["only_here"] == ["pdf:PDF_EMBEDDED_FILE:LOW"]
    assert changed["only_expected"] == ["pdf-chains:ENGINE_PDF_ATTACHMENTS_VERIFIED:INFO"]
    assert extra["expected_verdict"] is None  # nothing to compare with is not "the same"


def test_corrupt_documents_must_fail_closed():
    ok, bad = ov.compare([result("corrupt", "t.pdf", "reference", "UNABLE_TO_SCAN"),
                          result("corrupt", "t.pdf", "unified", "SAFE")], {})
    assert ok["same"] and not bad["same"]


def test_a_scan_without_isolation_or_with_the_other_engine_is_not_evidence():
    scanners = {n: "completed" for n in ov.main.engine_scanners("reference")}
    assert ov.scan_problem(result("s", "x", "reference", "SAFE", status=scanners), "reference") == ""
    assert ov.scan_problem(result("s", "x", "reference", "SAFE", missing=["capabilities_dropped"], status=scanners),
                           "reference")
    assert ov.scan_problem(result("s", "x", "unified", "SAFE", status=scanners), "unified")


def test_the_committed_windows_evidence_is_readable():
    expected = ov.expectations()
    assert len([k for k in expected if k[0] == "synthetic"]) == 32 and len([k for k in expected if k[0] == "corpus"]) == 66


def test_the_corpus_matches_its_manifests():
    items, problems = ov.corpus_items()
    assert problems == [] and len(items) == 33


def test_the_c7_cases_have_expected_verdicts_for_both_engines():
    c7 = {k: v for k, v in ov.expectations().items() if k[0] == "c7"}
    assert len(c7) == 12 and all(findings is None for _, findings in c7.values())


def test_every_claim_and_expected_result_holds_in_process():
    # The same sets, engines, comparison and claims as the VM run, without the worker subprocess:
    # a regression check on every commit (Windows and Linux CI) that no classification moved.
    from app import engine, worker
    from app.scanners import SCANNERS
    from evaluation.cases import cases, field_cases, verdicts

    corpus, _ = ov.corpus_items()
    results = []
    for name, items in (("synthetic", cases()), ("corpus", corpus), ("corrupt", ov.corrupt_items()),
                        ("c7", field_cases())):
        for item in items:
            for name_ in ov.ENGINES:
                report = (worker.analyse(SCANNERS, item["data"]) if name_ == "reference"
                          else engine.correlate(worker.analyse(engine.SCANNERS, item["data"])))
                results.append({"set": name, "id": item["id"], "engine": name_, "verdicts": verdicts(report),
                                "status": {s.name: s.status for s in report.scanners},
                                "findings": [{"scanner": f.scanner, "rule_id": f.rule_id, "severity": f.severity.value}
                                             for f in report.findings]})
    assert len(results) == 2 * (16 + 33 + 2 + 6)
    assert [r for r in ov.compare(results, ov.expectations()) if not r["same"]] == []
    assert [claim for claim, ok in ov.checks(results) if not ok] == []
