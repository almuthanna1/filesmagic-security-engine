"""Evaluation harness tests.

Everything here is synthetic and inert: plain text, the existing PDF/Office test
fixtures, and a /Launch PDF that only names a placeholder. "MALICIOUS" below is a
ground-truth *label* used to exercise the arithmetic, not a property of the bytes.

Functional tests of the arithmetic run with require_isolation=False (conftest scans in
process, without a worker); the strict-isolation tests at the end use the real worker.
"""

import csv
import functools
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

from app import main, worker
from evaluation import evaluate
from evaluation.evaluate import EvaluationAborted, ManifestError, load_manifest, run, view_metrics, wilson
from tests.office_fixtures import make_ooxml
from tests.pdf_fixtures import make_pdf
from tests.test_security import FORCED_WORKER

LINUX_REQUIRED = os.environ.get("FM_REQUIRE_LINUX_TESTS") == "1"

COLUMNS = evaluate.REQUIRED_COLUMNS


def write_sample(root: Path, rel: str, data: bytes) -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def row(sample_id, sha, path, file_type, truth, split="dev", **extra):
    base = dict(sample_id=sample_id, sha256=sha, path=path, file_type=file_type, ground_truth=truth,
                ground_truth_basis="synthetic test fixture", source="synthetic", source_ref="", acquired_date="2026-10-09",
                split=split, active_content="no", encrypted="no", tags="", notes="")
    base.update(extra)
    return base


def write_manifest(path: Path, rows: list[dict]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def dataset(tmp_path):
    root = tmp_path / "samples"
    rows = [
        row("B1", write_sample(root, "b/1.txt", b"plain benign text"), "b/1.txt", "txt", "BENIGN"),
        row("B2", write_sample(root, "b/2.pdf", make_pdf()), "b/2.pdf", "pdf", "BENIGN"),
        row("B3", write_sample(root, "b/3.docx", make_ooxml({})), "b/3.docx", "docx", "BENIGN", split="holdout"),
        # Benign but with JavaScript: the engine says SUSPICIOUS, a false positive in the block view.
        row("B4", write_sample(root, "b/4.pdf", make_pdf("/OpenAction << /S /JavaScript /JS (app.alert(1);) >>")),
            "b/4.pdf", "pdf", "BENIGN", active_content="yes"),
        row("M1", write_sample(root, "m/1.pdf", make_pdf("/OpenAction << /S /Launch /F (placeholder.txt) >>")),
            "m/1.pdf", "pdf", "MALICIOUS", split="holdout"),
        row("M2", write_sample(root, "m/2.xlsx", make_ooxml({"xl/macrosheets/sheet1.xml": "<xm/>"}, kind="xl")),
            "m/2.xlsx", "xlsx", "MALICIOUS"),
        # Labelled malicious but the engine finds nothing: a false negative.
        row("M3", write_sample(root, "m/3.txt", b"looks harmless"), "m/3.txt", "txt", "MALICIOUS"),
        # Malformed recognised PDF: UNABLE_TO_SCAN, excluded from the block view.
        row("M4", write_sample(root, "m/4.pdf", b"%PDF-1.7\nbroken"), "m/4.pdf", "pdf", "MALICIOUS"),
        row("D1", write_sample(root, "dup/1.pdf", make_pdf()), "dup/1.pdf", "pdf", "BENIGN"),  # duplicate of B2
        row("X1", write_sample(root, "x/1.txt", b"unclear origin"), "x/1.txt", "txt", "EXCLUDED", ground_truth_basis=""),
        row("T1", write_sample(root, "t/1.txt", b"standard test artifact stand-in"), "t/1.txt", "txt", "SECURITY_TEST"),
    ]
    return write_manifest(tmp_path / "manifest.csv", rows), root


# --------------------------------------------------------------------- metric arithmetic


def test_wilson_interval_matches_reference_values():
    # 8/10 at 95%: Wilson interval is approximately [0.490, 0.943].
    lo, hi = wilson(8, 10)
    assert lo == pytest.approx(0.4902, abs=1e-3) and hi == pytest.approx(0.9433, abs=1e-3)
    assert wilson(0, 10)[0] == 0.0 and wilson(10, 10)[1] == 1.0
    assert wilson(0, 0) is None


def test_view_metrics_formulas():
    rows = ([{"ground_truth": "MALICIOUS", "outcome": "MALICIOUS"}] * 8 + [{"ground_truth": "MALICIOUS", "outcome": "SAFE"}] * 2
            + [{"ground_truth": "BENIGN", "outcome": "SAFE"}] * 85 + [{"ground_truth": "BENIGN", "outcome": "SUSPICIOUS"}] * 5
            + [{"ground_truth": "BENIGN", "outcome": "UNABLE_TO_SCAN"}] * 3)
    m = view_metrics(rows, evaluate.VIEWS["block"])
    assert (m["TP"], m["FN"], m["FP"], m["TN"]) == (8, 2, 5, 85)
    assert m["excluded_benign"] == 3
    assert m["recall"] == 0.8 and m["false_negative_rate"] == 0.2
    assert m["precision"] == round(8 / 13, 4)
    assert m["specificity"] == round(85 / 90, 4) and m["false_positive_rate"] == round(5 / 90, 4)
    assert m["f1"] == round(2 * (8 / 13) * 0.8 / ((8 / 13) + 0.8), 4)
    assert m["accuracy"] == round(93 / 100, 4)
    assert m["balanced_accuracy"] == round((0.8 + 85 / 90) / 2, 4)


def test_views_treat_suspicious_and_unable_differently():
    rows = [{"ground_truth": "MALICIOUS", "outcome": "SUSPICIOUS"}, {"ground_truth": "BENIGN", "outcome": "UNABLE_TO_SCAN"}]
    block = view_metrics(rows, evaluate.VIEWS["block"])
    fail_closed = view_metrics(rows, evaluate.VIEWS["block_fail_closed"])
    conviction = view_metrics(rows, evaluate.VIEWS["conviction"])
    assert (block["TP"], block["FP"], block["excluded_benign"]) == (1, 0, 1)
    assert (fail_closed["TP"], fail_closed["FP"]) == (1, 1)  # unscannable benign file is blocked
    assert (conviction["TP"], conviction["FN"]) == (0, 1)  # SUSPICIOUS is not a conviction


def test_undefined_metrics_are_none_not_zero():
    m = view_metrics([], evaluate.VIEWS["block"])
    assert m["recall"] is None and m["precision"] is None and m["f1"] is None


# --------------------------------------------------------------------- end-to-end run


def test_run_produces_expected_outcomes_and_metrics(dataset, tmp_path):
    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out", require_isolation=False)
    per_sample = {r["sample_id"]: r for r in csv.DictReader((tmp_path / "out" / "per_sample.csv").open(encoding="utf-8"))}

    assert per_sample["B1"]["outcome"] == "SAFE"
    assert per_sample["B4"]["outcome"] == "SUSPICIOUS"
    assert per_sample["M1"]["outcome"] == "MALICIOUS" and "PDF_LAUNCH_ACTION" in per_sample["M1"]["rule_ids"]
    assert per_sample["M2"]["outcome"] == "SUSPICIOUS"
    assert per_sample["M3"]["outcome"] == "SAFE"
    assert per_sample["M4"]["outcome"] == "UNABLE_TO_SCAN"
    assert per_sample["D1"]["outcome"] == "SKIPPED" and per_sample["D1"]["duplicate_of"] == "B2"
    assert per_sample["X1"]["outcome"] == "SKIPPED"

    block = summary["views"]["block"]
    assert (block["TP"], block["FN"], block["FP"], block["TN"]) == (2, 1, 1, 3)
    assert block["excluded_malicious"] == 1
    conviction = summary["views"]["conviction"]
    assert (conviction["TP"], conviction["FN"], conviction["FP"], conviction["TN"]) == (1, 2, 0, 4)
    assert summary["coverage"]["MALICIOUS"]["not_scanned"] == 1
    assert summary["counts"]["duplicates_skipped"] == 1 and summary["counts"]["excluded_skipped"] == 1
    assert summary["distribution"]["SECURITY_TEST"]["SAFE"] == 1  # reported, never scored
    assert set(summary["views_by_file_type"]) == {"txt", "pdf", "docx", "xlsx"}
    assert summary["rule_hits"]["BENIGN"]  # false-positive rules are listed for analysis

    saved = json.loads((tmp_path / "out" / "summary.json").read_text(encoding="utf-8"))
    assert saved["environment"]["manifest_sha256"] and saved["environment"]["packages"]["pypdf"]
    report = (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")
    assert "# FilesMagic evaluation summary" in report
    assert "NOT A VALID RESEARCH RUN" in report  # functional run without strict isolation
    assert json.loads((tmp_path / "out" / "run_status.json").read_text())["strict_isolation_required"] is False


def test_split_filter(dataset, tmp_path):
    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out", split="holdout", require_isolation=False)
    assert summary["counts"]["scanned"] == 2  # B3, M1


def test_outputs_never_contain_sample_bytes(dataset, tmp_path):
    manifest, root = dataset
    run(manifest, root, tmp_path / "out", require_isolation=False)
    produced = b"".join(p.read_bytes() for p in (tmp_path / "out").iterdir())
    for sample in root.rglob("*"):
        if sample.is_file() and len(sample.read_bytes()) > 20:
            assert sample.read_bytes() not in produced


def test_oversized_sample_is_rejected_not_scanned(tmp_path, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)
    root = tmp_path / "samples"
    sha = write_sample(root, "big.txt", b"x" * 100)
    manifest = write_manifest(tmp_path / "m.csv", [row("B1", sha, "big.txt", "txt", "BENIGN")])
    summary = run(manifest, root, tmp_path / "out", require_isolation=False)
    assert summary["distribution"]["BENIGN"]["REJECTED"] == 1
    assert summary["views"]["block_fail_closed"]["FP"] == 1


def test_engine_exception_is_recorded_as_error(dataset, tmp_path):
    class Broken:
        def post(self, *args, **kwargs):
            raise RuntimeError("boom")

    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out", client=Broken(), key=evaluate.make_client()[1],
                  require_isolation=False)
    assert summary["distribution"]["BENIGN"]["ERROR"] == 4
    # Only the exception type is kept: exception text can quote sample content.
    assert summary["errors"] and summary["errors"][0]["message"] == "RuntimeError"
    assert summary["failure_reasons"]["BENIGN"] == {"harness_exception": 4}
    assert b"boom" not in b"".join(p.read_bytes() for p in (tmp_path / "out").iterdir())


# --------------------------------------------------------------------- manifest validation / safety


def test_sha256_mismatch_is_rejected(tmp_path):
    root = tmp_path / "samples"
    write_sample(root, "a.txt", b"hello")
    manifest = write_manifest(tmp_path / "m.csv", [row("A", "0" * 64, "a.txt", "txt", "BENIGN")])
    with pytest.raises(ManifestError, match="sha256 mismatch"):
        load_manifest(manifest, root)


def test_path_traversal_is_rejected(tmp_path):
    root = tmp_path / "samples"
    root.mkdir()
    sha = write_sample(tmp_path, "outside.txt", b"x")
    manifest = write_manifest(tmp_path / "m.csv", [row("A", sha, "../outside.txt", "txt", "BENIGN")])
    with pytest.raises(ManifestError, match="escapes the samples root"):
        load_manifest(manifest, root)


def test_samples_inside_repository_are_refused(tmp_path):
    manifest = write_manifest(tmp_path / "m.csv", [])
    with pytest.raises(ManifestError, match="inside the repository"):
        load_manifest(manifest, evaluate.REPO_ROOT / "evaluation")


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("ground_truth", "SUSPICIOUS", "ground_truth must be"),
        ("split", "train", "split must be"),
        ("active_content", "maybe", "active_content must be"),
        ("ground_truth_basis", "", "ground_truth_basis is required"),
        ("sample_id", "", "sample_id missing"),
    ],
)
def test_invalid_fields_are_rejected(tmp_path, field, value, message):
    root = tmp_path / "samples"
    sha = write_sample(root, "a.txt", b"x")
    entry = row("A", sha, "a.txt", "txt", "BENIGN")
    entry[field] = value
    manifest = write_manifest(tmp_path / "m.csv", [entry])
    with pytest.raises(ManifestError, match=message):
        load_manifest(manifest, root)


def test_missing_columns_are_rejected(tmp_path):
    (tmp_path / "m.csv").write_text("sample_id,sha256\nA,abc\n", encoding="utf-8")
    with pytest.raises(ManifestError, match="missing columns"):
        load_manifest(tmp_path / "m.csv", tmp_path)


def test_template_has_required_columns():
    header = (evaluate.REPO_ROOT / "evaluation" / "manifest_template.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.split(",") == COLUMNS


def test_harness_has_no_network_mode():
    source = (evaluate.REPO_ROOT / "evaluation" / "evaluate.py").read_text(encoding="utf-8")
    assert "onrender.com" not in source and "--url" not in source and "httpx.post" not in source


# --------------------------------------------------------------------- failure classification


def scanners(*entries):
    return [{"name": n, "status": st, "error_kind": k} for n, st, k in entries]


@pytest.mark.parametrize("status, body, reason", [
    (200, {"complete": True, "scanners": scanners(("pdf", "completed", None))}, ""),
    (200, {"complete": False, "scanners": scanners(("pdf", "not_applicable", None))}, "not_applicable"),
    (200, {"complete": False, "scanners": scanners(("pdf", "failed", "malformed_input"))}, "parser_failure"),
    (200, {"complete": False, "scanners": scanners(("pdf", "failed", "invalid_structure"),
                                                   ("office", "failed", "malformed_input"))}, "parser_failure"),
    (200, {"complete": False, "scanners": scanners(("pdf", "failed", "unexpected"))}, "scanner_error"),
    (200, {"complete": False, "scanners": scanners(("pdf", "failed", "worker"))}, "worker_failure"),
    # Strict refusal: scanners failed without a kind, and isolation_missing names the controls.
    (200, {"complete": False, "isolation_required": True, "isolation_missing": ["network_verified"],
           "scanners": scanners(("pdf", "failed", None))}, "isolation_unavailable"),
    (413, None, "rejected_size"),
    (500, None, "http_error"),
])
def test_failure_reason_classification(status, body, reason):
    assert evaluate.failure_reason(status, body) == reason


# --------------------------------------------------------------------- strict isolation (Phase C9)


def use_worker(monkeypatch, off="None", cmd=None):
    """Real API and real worker main(), strict mode, with the isolation outcome forced (FORCED_WORKER:
    off names the one required control that fails; "None" = every control holds)."""
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    cmd = cmd or [sys.executable, "-B", "-c", FORCED_WORKER, off]
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=cmd))


def outputs(out: Path):
    per_sample = {r["sample_id"]: r for r in csv.DictReader((out / "per_sample.csv").open(encoding="utf-8"))}
    records = {r["sample_id"]: r for r in json.loads((out / "per_sample.json").read_text(encoding="utf-8"))}
    return per_sample, records, json.loads((out / "summary.json").read_text(encoding="utf-8"))


def test_strict_run_records_isolation_and_keeps_malformed_documents(monkeypatch, dataset, tmp_path):
    use_worker(monkeypatch)
    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out")
    per_sample, records, saved = outputs(tmp_path / "out")

    status = saved["run_status"]
    assert status["status"] == "completed" and status["strict_isolation_required"] is True
    pre = status["preflight"]
    assert pre["verdict"] == "SAFE" and pre["complete"] is True and pre["isolation_missing"] == []
    assert pre["isolation_required"] is True and pre["request_id"]

    scanned = [r for r in records.values() if r["outcome"] not in ("SKIPPED",)]
    for r in scanned:
        assert r["isolation_required"] is True and r["isolation_missing"] == "", r
        assert all(r["isolation"][k] is True for k in worker.REQUIRED_CONTROLS), r
        assert r["request_id"] and r["ruleset_sha256"] == main.VERSIONS["ruleset_sha256"]
    # A malformed document is a legitimate UNABLE_TO_SCAN, not an isolation failure; the run goes on.
    assert per_sample["M4"]["outcome"] == "UNABLE_TO_SCAN" and per_sample["M4"]["failure_reason"] == "parser_failure"
    assert "pdf=failed:malformed_input" in per_sample["M4"]["scanner_status"]
    assert per_sample["M4"]["complete"] == "False" and per_sample["B1"]["complete"] == "True"
    assert "capabilities_dropped=True" in per_sample["B1"]["isolation"]
    # Metrics are exactly those of the functional run: strict mode changes evidence, not arithmetic.
    block = summary["views"]["block"]
    assert (block["TP"], block["FN"], block["FP"], block["TN"]) == (2, 1, 1, 3)
    assert summary["isolation"]["samples_with_verified_isolation"] == len(scanned)
    assert summary["failure_reasons"]["MALICIOUS"] == {"parser_failure": 1}
    env = saved["environment"]
    assert env["strict_isolation_configured"] is True and env["worker_memory_measured"] is False
    assert "peak_rss_mib" not in env and "harness_peak_rss_mib" in env
    assert env["ruleset_sha256"] == main.VERSIONS["ruleset_sha256"] and env["engine_version"]
    assert "NOT A VALID RESEARCH RUN" not in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")
    # Scanner error text (which can quote content) is never exported, only kinds and types.
    produced = "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "out").iterdir())
    assert "analysis failed" not in produced and "Traceback" not in produced


@pytest.mark.parametrize("off", ["network_namespace", "capabilities_dropped", "network_verified"])
def test_preflight_aborts_before_the_dataset_is_read(monkeypatch, tmp_path, off):
    use_worker(monkeypatch, off)

    def must_not_read(*args):
        raise AssertionError("the dataset must not be read after a failed preflight")

    monkeypatch.setattr(evaluate, "load_manifest", must_not_read)
    with pytest.raises(EvaluationAborted, match="preflight failed"):
        run(tmp_path / "manifest.csv", tmp_path / "samples", tmp_path / "out")
    status = json.loads((tmp_path / "out" / "run_status.json").read_text(encoding="utf-8"))
    assert status["status"] == "aborted_preflight" and status["preflight"]["isolation_missing"] == [off]
    assert status["preflight"]["failure_reason"] == "isolation_unavailable"
    assert not (tmp_path / "out" / "per_sample.csv").exists()


def test_preflight_aborts_when_strict_mode_is_not_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", False)

    class NoScans:
        def post(self, *args, **kwargs):
            raise AssertionError("no scan may run without strict mode")

    with pytest.raises(EvaluationAborted, match="SECURITY_ENGINE_REQUIRE_ISOLATION=1"):
        run(tmp_path / "manifest.csv", tmp_path / "samples", tmp_path / "out", client=NoScans())
    status = json.loads((tmp_path / "out" / "run_status.json").read_text(encoding="utf-8"))
    assert status["status"] == "aborted_preflight" and status["preflight"] == {"strict_isolation_configured": False}
    assert status["reason"] == "strict isolation is not configured: set SECURITY_ENGINE_REQUIRE_ISOLATION=1"


def test_real_worker_strict_preflight_reflects_the_platform(monkeypatch):
    # No forcing: the real worker decides. Windows has no namespaces and must fail; Linux CI,
    # where namespaces are enabled, must pass. Elsewhere only consistency is checked.
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    monkeypatch.setattr(main, "run_scan", worker.run)
    try:
        evidence, passed = evaluate.strict_preflight(*evaluate.make_client()), True
    except EvaluationAborted as e:
        evidence, passed = e.args[1], False
    if sys.platform == "win32":
        assert not passed and {"network_namespace", "capabilities_dropped"} <= set(evidence["isolation_missing"])
    if LINUX_REQUIRED:
        assert passed, evidence
    assert passed == (evidence["isolation_missing"] == []), evidence


class SwitchWorker:
    """Passes requests to the real client; from the given call on, scans use another worker."""

    def __init__(self, monkeypatch, client, at_call, cmd):
        self.monkeypatch, self.client, self.at_call, self.cmd, self.calls = monkeypatch, client, at_call, cmd, 0

    def post(self, *args, **kwargs):
        self.calls += 1
        if self.calls == self.at_call:
            self.monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, cmd=self.cmd))
        return self.client.post(*args, **kwargs)


def test_isolation_lost_mid_run_stops_scanning_and_fails_the_run(monkeypatch, dataset, tmp_path):
    use_worker(monkeypatch)
    client, key = evaluate.make_client()
    # Call 1 is the preflight, call 2 sample B1; from call 3 (B2) network verification fails.
    lossy = SwitchWorker(monkeypatch, client, 3, [sys.executable, "-B", "-c", FORCED_WORKER, "network_verified"])
    manifest, root = dataset
    with pytest.raises(EvaluationAborted, match="isolation was lost"):
        run(manifest, root, tmp_path / "out", client=lossy, key=key)
    per_sample, _, saved = outputs(tmp_path / "out")
    assert saved["run_status"]["status"] == "failed_isolation_lost"
    assert per_sample["B1"]["outcome"] == "SAFE"
    assert per_sample["B2"]["outcome"] == "UNABLE_TO_SCAN" and per_sample["B2"]["failure_reason"] == "isolation_unavailable"
    assert per_sample["B2"]["isolation_missing"] == "network_verified"
    assert {per_sample[s]["outcome"] for s in ("B3", "B4", "M1", "M2", "M3", "M4", "T1")} == {"NOT_RUN"}
    assert lossy.calls == 3  # nothing was scanned after the loss
    assert saved["counts"]["not_run"] == 7
    assert "NOT A VALID RESEARCH RUN" in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")


def test_worker_crashes_are_recorded_without_stopping_the_run(monkeypatch, dataset, tmp_path):
    # A crashing or timed-out worker sends no isolation report; that is a per-sample failure
    # (it can be document-caused), not a loss of isolation.
    use_worker(monkeypatch)
    client, key = evaluate.make_client()
    crash = SwitchWorker(monkeypatch, client, 2, [sys.executable, "-B", "-m", "tests.fake_worker", "crash"])
    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out", client=crash, key=key)
    per_sample, _, saved = outputs(tmp_path / "out")
    assert saved["run_status"]["status"] == "completed"
    assert all(per_sample[s]["failure_reason"] == "worker_failure" and per_sample[s]["outcome"] == "UNABLE_TO_SCAN"
               for s in ("B1", "B2", "M1", "T1"))
    assert summary["isolation"]["samples_without_isolation_report"] == summary["counts"]["scanned"]

