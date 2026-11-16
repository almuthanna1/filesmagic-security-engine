import pytest

from evaluation import poster


def result(case, verdict, findings, trials):
    return {"id": case, "indicator": "x", "sha256": "0" * 64, "deterministic": True,
            "verdicts": {"aggregate": verdict}, "status": {"a": "completed", "b": "not_applicable"},
            "findings": [dict(scanner=s, rule_id=r, severity=v, description="d") for s, r, v in findings],
            "timing_ms": {"harness_wall": {}},
            "trials": [{"harness_wall_ms": w, "scanner_ms": {"a": a, "b": 0.0}} for w, a in trials]}


def test_start_up_is_wall_time_minus_detection_work_and_only_completed_scanners_count():
    t = poster.timing({"c": result("c", "SAFE", [], [(100.0, 1.0), (120.0, 3.0)])})
    assert t["scanning"]["median_ms"] == 2.0 and t["startup_and_ipc"]["median_ms"] == 108.0
    assert list(t["per_scanner"]) == ["a"]  # b was not applicable


def test_added_removed_and_qualified_findings_and_caption_check(monkeypatch):
    case = "5a-pdf-auto-js-unrelated-attachment"
    monkeypatch.setattr(poster, "SCENARIOS", [("s", [case])])
    ref = {case: result(case, "MALICIOUS", [("pdf", "OLD", "HIGH")], [(1, 0)])}
    uni = {case: result(case, "SUSPICIOUS", [("pdf-chains", "NEW", "MEDIUM"), ("pdf-chains", "ENGINE_CORRELATION", "INFO")],
                        [(1, 0)])}
    row, = poster.compare(ref, uni)
    assert (row["added"], row["removed"], row["qualified"]) == ([("pdf-chains", "NEW", "MEDIUM")], [("pdf", "OLD", "HIGH")], ["d"])
    poster.check_captions([row])  # 5a's caption says the verdict changed, and it did
    with pytest.raises(ValueError):
        poster.check_captions([{**row, "unified": "MALICIOUS"}])
