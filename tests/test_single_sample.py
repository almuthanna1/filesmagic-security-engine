"""evaluation.single_sample: gates before the sample is read, hash check before any scan, redacted
metadata-only output, and the pre-registered comparison. Inert fixtures only; the isolated worker is
replaced by the same scanners in process (the VM run uses the real worker)."""

import hashlib
import json
from argparse import Namespace
from pathlib import Path

import pytest

from app import engine, worker
from app.scanners import SCANNERS
from evaluation import cases as synthetic
from evaluation import single_sample as ss
from evaluation.cases import verdicts
from evaluation.evaluate import latency

EXPECTATIONS = ss.REPO / "evaluation" / "expectations"
GOOD = {"host_network": {"offline": True}, "engine_commit": "a" * 40, "working_tree_dirty": False,
        "dependency_drift": [], "strict_isolation_configured": True, "confinement": ss.ov.CONFINEMENT}
URL = "https://bad.example/payload.dll"


def in_process(item, trials, cmd, extra=()):
    """scan_case's result shape, from the scanners run in this process."""
    name = "unified" if "--engine=unified" in cmd else "reference"
    report = worker.analyse(SCANNERS if name == "reference" else engine.SCANNERS, item["data"])
    report = report if name == "reference" else engine.correlate(report)
    findings = [dict(scanner=f.scanner, rule_id=f.rule_id, severity=f.severity.value, description=f.description)
                for f in report.findings] + list(extra)
    return {"id": item["id"], "verdicts": verdicts(report), "deterministic": True,
            "status": {s.name: s.status for s in report.scanners}, "findings": findings, "isolation_missing": [],
            "timing_ms": {"harness_wall": latency([12.0]), **{s.name: latency([1.0]) for s in report.scanners}}}


def args(tmp_path, sample_id, sample=None, sha256=None):
    exp = json.loads((EXPECTATIONS / f"{sample_id}.json").read_text())
    if sample is None:
        sample = tmp_path / f"{sample_id}.bin"
        sample.write_bytes(ss.inert_fixtures()[sample_id])
    return Namespace(sample=sample, sha256=sha256 or exp["sample_sha256"], expectations=EXPECTATIONS / f"{sample_id}.json",
                     expect_commit="a" * 40, trials=1, out=tmp_path / "out")


@pytest.fixture
def gates_hold(monkeypatch):
    monkeypatch.setattr(ss, "frozen_problems", lambda: [])
    monkeypatch.setattr(ss, "tracked", lambda path: True)


def test_redaction_withholds_document_text():
    text = ss.redact(f"Target '{URL}' via \\\\host\\share and 10.0.0.1, also {URL}. Evidence: Module1.Evil -> Shell")
    assert "bad.example" not in text and "host" not in text and "10.0.0.1" not in text and "Evil" not in text
    assert text.count("[withheld") == 5 and ss.redact("x" * 999).endswith("…") and len(ss.redact("x" * 999)) == ss.MAX_TEXT
    assert ss.redact("Macro code runs automatically via: Document_Open.") == "Macro code runs automatically via: Document_Open."


def test_this_branch_carries_the_frozen_engine():
    assert ss.frozen_problems() == []


def test_only_committed_files_inside_the_repository_count_as_registered(tmp_path):
    assert ss.tracked(ss.REPO / "app" / "main.py")
    assert not ss.tracked(tmp_path / "x.json")


@pytest.mark.parametrize("path", sorted(EXPECTATIONS.glob("*.json")), ids=lambda p: p.stem)
def test_expectation_files_are_well_formed(path):
    exp = json.loads(path.read_text())
    assert path.stem == exp["sample_id"] and set(exp["engines"]) == set(ss.ENGINES)
    assert all(e["verdict"] in ss.RANK for e in exp["engines"].values())
    assert exp["ground_truth"] in ("MALICIOUS", "BENIGN", "SECURITY_TEST")


def test_the_emotet_expectations_name_the_preregistered_sample():
    exp = json.loads((EXPECTATIONS / "m5-emotet-e50c941c.json").read_text())
    prereg = (ss.REPO / exp["preregistration"]).read_text(encoding="utf-8")
    assert exp["sample_sha256"] in prereg and "**Reference verdict: MALICIOUS**" in prereg
    assert "**Unified verdict: MALICIOUS**" in prereg


def test_inert_fixtures_are_the_registered_files():
    for name, data in ss.inert_fixtures().items():
        assert hashlib.sha256(data).hexdigest() == json.loads((EXPECTATIONS / f"{name}.json").read_text())["sample_sha256"]


@pytest.mark.parametrize("name", ["inert-ole-vba-storage", "inert-benign-docx", "inert-truncated-docx"])
def test_inert_fixtures_meet_their_expectations_end_to_end(monkeypatch, tmp_path, gates_hold, name):
    monkeypatch.setattr(synthetic, "scan_case", in_process)
    a = args(tmp_path, name)
    assert ss.run(a, GOOD) == 0
    doc = json.loads((a.out / "results.json").read_text())
    assert doc["assessment"]["outcome"] == "PASS", doc["assessment"]
    assert all(c["held"] for c in doc["assessment"]["checks"])
    for line in (a.out / "SHA256SUMS").read_text().splitlines():
        digest, file = line.split("  ")
        assert hashlib.sha256((a.out / file).read_bytes()).hexdigest() == digest


def test_report_is_offline_and_redacted(monkeypatch, tmp_path, gates_hold):
    leak = {"scanner": "office", "rule_id": "X", "severity": "INFO", "description": f"<script>alert(1)</script> '{URL}'"}
    monkeypatch.setattr(synthetic, "scan_case", lambda item, trials, cmd: in_process(item, trials, cmd, [leak]))
    a = args(tmp_path, "inert-benign-docx")
    ss.run(a, GOOD)
    page, results = (a.out / "report.html").read_text(), (a.out / "results.json").read_text()
    assert "<script" not in page and "http" not in page.replace("http-equiv", "") and "src=" not in page
    assert "bad.example" not in page + results
    fixture = ss.inert_fixtures()["inert-benign-docx"]
    assert fixture[:64].hex() not in results and "PK\\u0003" not in results  # no sample bytes


def test_a_hash_mismatch_stops_before_any_scan(monkeypatch, tmp_path, gates_hold):
    monkeypatch.setattr(synthetic, "scan_case", lambda *a: pytest.fail("scanned a file whose hash did not match"))
    other = tmp_path / "other.bin"
    other.write_bytes(ss.inert_fixtures()["inert-truncated-docx"])
    a = args(tmp_path, "inert-benign-docx", sample=other)
    assert ss.run(a, GOOD) == 3
    status = json.loads((a.out / "run_status.json").read_text())
    assert status["status"] == "stopped" and "is not the expected" in status["problems"][0]


def test_sha256_must_be_the_registered_one(monkeypatch, tmp_path, gates_hold):
    monkeypatch.setattr(ss, "read_sample", lambda *a: pytest.fail("read the sample"))
    a = args(tmp_path, "inert-benign-docx", sha256="0" * 64)
    assert ss.run(a, GOOD) == 3


@pytest.mark.parametrize("change", [{"confinement": "unconfined"}, {"host_network": {"offline": False}},
                                    {"strict_isolation_configured": False}, {"working_tree_dirty": True}])
def test_a_failed_gate_never_reads_the_sample(monkeypatch, tmp_path, gates_hold, change):
    monkeypatch.setattr(ss, "read_sample", lambda *a: pytest.fail("read the sample"))
    assert ss.run(args(tmp_path, "inert-benign-docx"), GOOD | change) == 3


def test_unregistered_expectations_or_a_changed_engine_stop(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "read_sample", lambda *a: pytest.fail("read the sample"))
    monkeypatch.setattr(ss, "tracked", lambda path: False)
    monkeypatch.setattr(ss, "frozen_problems", lambda: ["app differs from the frozen release"])
    a = args(tmp_path, "inert-benign-docx")
    assert ss.run(a, GOOD) == 3
    problems = json.loads((a.out / "run_status.json").read_text())["problems"]
    assert "app differs from the frozen release" in problems and any("is not committed" in p for p in problems)


def test_existing_output_is_never_overwritten(tmp_path):
    a = args(tmp_path, "inert-benign-docx")
    a.out.mkdir()
    assert ss.run(a, GOOD) == 3 and list(a.out.iterdir()) == []


def test_symlinks_directories_and_oversized_files_are_refused(tmp_path):
    big = tmp_path / "big.bin"
    big.write_bytes(b"\0" * (ss.MAX_BYTES + 1))
    assert ss.read_sample(big, "0" * 64)[0] is None and ss.read_sample(tmp_path, "0" * 64)[0] is None


def test_lost_isolation_stops_the_run(monkeypatch, tmp_path, gates_hold):
    def lost(item, trials, cmd):
        r = in_process(item, trials, cmd)
        return r | {"isolation_missing": ["capabilities_dropped"]} if item["id"] != "preflight" else r
    monkeypatch.setattr(synthetic, "scan_case", lost)
    a = args(tmp_path, "inert-benign-docx")
    assert ss.run(a, GOOD) == 3
    assert "assessment" not in json.loads((a.out / "results.json").read_text())


def result(engine_, verdict, *rules, deterministic=True, error=None):
    if error:
        return {"engine": engine_, "worker_error": error}
    return {"engine": engine_, "verdicts": {"aggregate": verdict}, "deterministic": deterministic, "status": {},
            "isolation_missing": [], "timing_ms": {"harness_wall": latency([5.0])},
            "findings": [dict(zip(("scanner", "rule_id", "severity"), r.split(":"))) for r in rules]}


EMOTET = json.loads((EXPECTATIONS / "m5-emotet-e50c941c.json").read_text())
AUTOEXEC, CAPABILITY = "office:OFFICE_MACRO_AUTOEXEC:MEDIUM", "office:OFFICE_MACRO_DANGEROUS_CAPABILITY:MEDIUM"


@pytest.mark.parametrize("results, outcome, defect", [
    ([result("reference", "MALICIOUS", AUTOEXEC, CAPABILITY), result("unified", "MALICIOUS", AUTOEXEC, CAPABILITY)],
     "PASS", None),
    ([result("reference", "SUSPICIOUS", AUTOEXEC), result("unified", "SUSPICIOUS", AUTOEXEC)], "PARTIAL", None),
    ([result("reference", "MALICIOUS", AUTOEXEC, CAPABILITY), result("unified", "SUSPICIOUS", AUTOEXEC)], "FAIL", "D1"),
    ([result("reference", "SAFE"), result("unified", "SAFE")], "FAIL", "D5"),
    ([result("reference", "MALICIOUS", AUTOEXEC, CAPABILITY), result("unified", None, error="WorkerError: timeout")],
     "FAIL", "D3"),
    ([result("reference", "MALICIOUS", AUTOEXEC, CAPABILITY, deterministic=False),
      result("unified", "MALICIOUS", AUTOEXEC, CAPABILITY)], "FAIL", "D4"),
    ([result("reference", "MALICIOUS", "yara-x:OLE_Office_VBA_Macros:MEDIUM", "office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH"),
      result("unified", "MALICIOUS", "office:OFFICE_MACRO_AUTOEXEC_EXECUTION:HIGH")], "NOT AS PREDICTED", None),
])
def test_acceptance_follows_the_preregistration(results, outcome, defect):
    a = ss.assess(results, EMOTET)
    assert a["outcome"] == outcome
    assert (defect is None and not a["defects"]) or any(d.startswith(defect) for d in a["defects"])


def test_the_alternative_vba_outcome_is_reported_as_the_alternative():
    a = ss.assess([result("reference", "MALICIOUS"),
                   result("unified", "MALICIOUS", "vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH")], EMOTET)
    row = next(c for c in a["checks"] if "alternative" in c["prediction"])
    assert not row["held"] and row["observed"] == "vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY:HIGH"
