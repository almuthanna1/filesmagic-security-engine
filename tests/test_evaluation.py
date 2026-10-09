"""Evaluation harness tests.

Everything here is synthetic and inert: plain text, the existing PDF/Office test
fixtures, and a /Launch PDF that only names a placeholder. "MALICIOUS" below is a
ground-truth *label* used to exercise the arithmetic, not a property of the bytes.
"""

import csv
import hashlib
import json
from pathlib import Path

import pytest

from evaluation import evaluate
from evaluation.evaluate import ManifestError, load_manifest, run, view_metrics, wilson
from tests.office_fixtures import make_ooxml
from tests.pdf_fixtures import make_pdf

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
    summary = run(manifest, root, tmp_path / "out")
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
    assert "# FilesMagic evaluation summary" in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")


def test_split_filter(dataset, tmp_path):
    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out", split="holdout")
    assert summary["counts"]["scanned"] == 2  # B3, M1


def test_outputs_never_contain_sample_bytes(dataset, tmp_path):
    manifest, root = dataset
    run(manifest, root, tmp_path / "out")
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
    summary = run(manifest, root, tmp_path / "out")
    assert summary["distribution"]["BENIGN"]["REJECTED"] == 1
    assert summary["views"]["block_fail_closed"]["FP"] == 1


def test_engine_exception_is_recorded_as_error(dataset, tmp_path):
    class Broken:
        def post(self, *args, **kwargs):
            raise RuntimeError("boom")

    manifest, root = dataset
    summary = run(manifest, root, tmp_path / "out", client=Broken())
    assert summary["distribution"]["BENIGN"]["ERROR"] == 4
    assert summary["errors"] and "boom" in summary["errors"][0]["message"]


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
