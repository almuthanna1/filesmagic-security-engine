"""End-to-end /scan tests for engine selection: request -> token -> worker -> verdict -> response.

Most tests run the selected engine in this process (tests/conftest.py); the ones marked
"real worker" run it in the isolated worker subprocess, exactly as the deployed API does.
The acceptance test replays the frozen evaluation matrix (docs/evidence/custom-engine-fp-fixes)
through the API for both engines. If detection changes on purpose, re-freeze that evidence.
"""

import asyncio
import functools
import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import engine as unified_engine
from app import main, worker
from app.models import Severity
from app.scanners import office
from evaluation.cases import cases
from evaluation.offline_validation import unified_expected
from tests import custom_fixtures as fx
from tests.scan_client import FORMAT_ONLY, auth_headers, post_scan
from tests.test_vba_chains import RELATED, SourceOnlyOfficeParser
from tests.pdf_fixtures import make_pdf

client = TestClient(main.app)
CASE = {c["id"]: c["data"] for c in cases()}
FROZEN = Path(__file__).resolve().parent.parent / "docs/evidence/custom-engine-fp-fixes"
UNIFIED_SCANNERS = ["signatures", "office", "pdf", "custom", "pdf-chains", "pdf-integrity", "vba-chains", "ooxml-links", "word-fields"]
CORRUPT_PDF = b"%PDF-1.7\n1 0 obj\n<< /Length 10 >>\nstream\nno end marker follows"


@pytest.fixture
def research():
    """Formerly enabled the research engines; the unified engine is now the only one, always on."""


def scan(data: bytes, engine: str | None = None, filename: str = "upload", **kw):
    params = {"engine": engine} if engine else None
    return client.post("/scan", content=data, headers=auth_headers(data, filename), params=params, **kw)


# The frozen unified run predates the custom signature matcher, which replaced both YARA-X scanners
# ("yara-x" and "yara-x-engine") by one scanner, "signatures", with the same rule IDs and severities.
RENAMED = {"yara-x": "signatures", "yara-x-engine": "signatures"}


def renamed(item: str) -> str:
    scanner, rest = item.split(":", 1)
    return f"{RENAMED.get(scanner, scanner)}:{rest}"


def rules(body: dict) -> list[str]:
    return sorted({f"{f['scanner']}:{f['rule_id']}:{f['severity']}" for f in body["findings"] if f["severity"] != "INFO"})


# ----------------------------------------------------------------------------- selection


def test_the_default_engine_is_the_unified_engine():
    body = post_scan(client, CASE["1-pdf-clean"]).json()
    assert body["engine"] == "unified" and [s["name"] for s in body["scanners"]] == UNIFIED_SCANNERS
    assert body["versions"]["commit"] and len(body["versions"]["engine_ruleset_sha256"]) == 64
    assert body["versions"]["ruleset_sha256"] == body["versions"]["engine_ruleset_sha256"]  # one ruleset
    assert "yara-x" not in body["versions"]


def test_the_retired_reference_engine_is_refused_and_the_token_survives():
    data = CASE["1-pdf-clean"]
    headers = auth_headers(data)
    refused = client.post("/scan", content=data, headers=headers, params={"engine": "reference"})
    assert refused.status_code == 410 and refused.json()["code"] == "ENGINE_RETIRED"
    # Refused before the token was checked: the same single-use token still works once.
    assert client.post("/scan", content=data, headers=headers).json()["engine"] == "unified"


def test_an_unknown_engine_is_refused():
    response = scan(CASE["1-pdf-clean"], "fastest")
    assert response.status_code == 400 and "Unknown engine" in response.json()["detail"]


def test_health_lists_only_the_unified_engine():
    health = client.get("/health").json()
    assert health["engines"] == ["unified"] and health["default_engine"] == "unified"
    assert health["scanners_registered"] == len(UNIFIED_SCANNERS)


# ----------------------------------------------------------------------------- acceptance


# (Not named "engine": tests/conftest.py has an autouse fixture of that name.)
@pytest.mark.parametrize("engine_name", ["unified"])  # the reference engine's frozen run: not reproducible
@pytest.mark.parametrize("case", sorted(CASE))
def test_every_frozen_case_reproduces_through_the_api(research, engine_name, case):
    frozen = {r["id"]: r for r in json.loads((FROZEN / engine_name / "results.json").read_text())["results"]}[case]
    body = scan(CASE[case], engine_name, filename=f"{case}.bin").json()
    assert body["engine"] == engine_name
    assert body["verdict"] == frozen["verdicts"]["aggregate"]
    status = {s["name"]: s["status"] for s in body["scanners"]}
    if engine_name == "unified":
        frozen["rules"] = unified_expected(frozen["rules"])  # renames and the Phase 4 merge
        frozen["status"] = {RENAMED.get(n, n): v for n, v in frozen["status"].items()}
        status.pop("word-fields")  # C7, added after the frozen run; its status: tests/test_word_fields.py
        status.pop("pdf-integrity")  # post-freeze coverage scanner; dedicated regressions below
    assert rules(body) == frozen["rules"]
    assert status == frozen["status"]
    # The hash of the bytes sent, not the frozen one: DEFLATE output (the Office fixtures are ZIPs)
    # depends on the zlib build, so the same fixture can have different bytes on another platform.
    assert body["sha256"] == hashlib.sha256(CASE[case]).hexdigest()


def test_all_four_verdicts_through_the_unified_engine(research):
    verdicts = {name: scan(data, "unified").json()["verdict"] for name, data in [
        ("safe", CASE["1-pdf-clean"]), ("suspicious", CASE["5a-pdf-auto-js-unrelated-attachment"]),
        ("malicious", CASE["5b-pdf-auto-js-exports-attachment"]), ("unable", CORRUPT_PDF)]}
    assert verdicts == {"safe": "SAFE", "suspicious": "SUSPICIOUS", "malicious": "MALICIOUS",
                        "unable": "UNABLE_TO_SCAN"}


def test_incomplete_content_coverage_fails_closed_without_changing_complete(research):
    bad_lzw = bytes.fromhex("789c730ae15250d0773354303251084903b2cd8d80c840212405c8d608c82f492cc9d75408c9e2720de10200cb0109c8")
    data = make_pdf(objects={4: fx.stream_object("/Filter /LZWDecode", bad_lzw)})
    body = scan(data, "unified").json()
    assert body["verdict"] == "UNABLE_TO_SCAN" and body["complete"] and not body["coverage_complete"]
    assert {issue["code"] for issue in body["coverage_issues"]} == {"PDF_CONTENT_LZW_DECODE_FAILED"}


def test_security_evidence_still_wins_over_incomplete_coverage(research):
    bad_lzw = bytes.fromhex("789c730ae15250d0773354303251084903b2cd8d80c840212405c8d608c82f492cc9d75408c9e2720de10200cb0109c8")
    data = make_pdf("/OpenAction << /S /Launch /F (calc.exe) >>", objects={4: fx.stream_object("/Filter /LZWDecode", bad_lzw)})
    body = scan(data, "unified").json()
    assert body["verdict"] == "MALICIOUS" and not body["coverage_complete"]


@pytest.mark.parametrize("kind", ["docx", "xlsx", "pptx"])
def test_word_excel_and_powerpoint_documents_scan_clean(research, kind):
    data = fx.office_package(kind)
    for engine_name, names in (("unified", UNIFIED_SCANNERS),):
        body = scan(data, engine_name).json()
        assert body["verdict"] == "SAFE" and body["complete"] and [s["name"] for s in body["scanners"]] == names
        assert body["detected_format"] == "zip"
        assert "not a guarantee" in body["message"]


def test_structured_evidence_reaches_the_response(research):
    body = scan(CASE["5b-pdf-auto-js-exports-attachment"], "unified").json()
    chain = next(f for f in body["findings"] if f["rule_id"] == "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT")
    assert chain["evidence"] == ["catalog /OpenAction: JavaScript (object 7 0) (exports 'f')"]
    notes = {f["scanner"]: f["evidence"] for f in body["findings"] if f["rule_id"] == "ENGINE_CORRELATION"}
    assert "PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD" in notes["pdf-chains"][0]
    assert any(n.startswith("merged PDF_EMBEDDED_FILE (pdf)") for n in notes["pdf-chains"])
    relationship = scan(CASE["6c-docx-template-referenced-by-settings"], "unified").json()
    on_open = next(f for f in relationship["findings"] if f["rule_id"] == "ENGINE_OFFICE_EXTERNAL_ON_OPEN")
    assert on_open["evidence"][0].startswith("package -> word/document.xml (officedocument) -> word/settings.xml")


def test_the_refined_signature_replaces_the_reference_match(research):
    body = scan(CASE["2-pdf-form-keystroke-js"], "unified").json()
    ids = {f["rule_id"] for f in body["findings"]}
    assert "PDF_JavaScript_With_Automatic_Action" not in ids and "ENGINE_PDF_USER_TRIGGERED_SCRIPT" in ids


def test_vba_call_paths_reach_the_response(research, monkeypatch):
    # Container parsing replaced by inert source strings (no VBA project is built); see test_vba_chains.
    from app.engine import vba_analysis
    monkeypatch.setattr(SourceOnlyOfficeParser, "modules", [("Module1", RELATED)])
    monkeypatch.setattr(vba_analysis, "VBA_Parser", SourceOnlyOfficeParser)
    from tests.test_vba_chains import DOCM
    body = scan(DOCM, "unified").json()
    path = next(f for f in body["findings"] if f["rule_id"] == "ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY")
    assert path["evidence"] == ["Module1.AutoOpen -> Module1.Prepare -> Module1.RunTool "
                                "(execute: Shell starts a program (line 8, command 'placeholder'))"]
    assert body["verdict"] == "MALICIOUS" and path["severity"] == Severity.HIGH.value


# ----------------------------------------------------------------------------- failures


def test_oversized_uploads_are_refused_for_the_unified_engine(research):
    data = b"x" * (main.MAX_UPLOAD_BYTES + 1)
    assert scan(data, "unified").status_code == 413


def test_a_crashed_worker_fails_the_unified_scan_closed(research, monkeypatch):
    async def crashed(data, engine="unified"):
        raise worker.WorkerError("scan worker exited abnormally (status 1)")
    monkeypatch.setattr(main, "run_scan", crashed)
    body = scan(CASE["5b-pdf-auto-js-exports-attachment"], "unified").json()
    assert body["verdict"] == "UNABLE_TO_SCAN" and not body["complete"]
    assert [(s["name"], s["status"], s["error_kind"]) for s in body["scanners"]] == \
        [(n, "failed", "worker") for n in UNIFIED_SCANNERS]


def test_a_worker_that_ran_the_other_engine_is_not_accepted(research, monkeypatch):
    async def wrong_engine(data, engine="unified"):  # a stale worker: answers with the retired roster
        return worker.analyse(FORMAT_ONLY, data)
    monkeypatch.setattr(main, "run_scan", wrong_engine)
    body = scan(CASE["5b-pdf-auto-js-exports-attachment"], "unified").json()
    assert body["verdict"] == "UNABLE_TO_SCAN" and body["findings"] == []
    assert "unexpected set of scanners for the unified engine" in body["scanners"][0]["error"]


# ----------------------------------------------------------------------------- real worker


def test_real_worker_runs_each_engine_and_reports_scanner_durations(research, monkeypatch):
    monkeypatch.setattr(main, "run_scan", worker.run)
    data = CASE["5a-pdf-auto-js-unrelated-attachment"]
    unified = scan(data, "unified").json()
    assert unified["verdict"] == "SUSPICIOUS"  # the frozen reference run said MALICIOUS: unrelated attachment
    assert [s["name"] for s in unified["scanners"]] == UNIFIED_SCANNERS
    assert all(s["duration_ms"] is not None for s in unified["scanners"])
    assert unified["isolation"]["process"] is True and unified["isolation"]["audit_hook"] is True


def test_real_worker_timeout_fails_the_unified_scan_closed(research, monkeypatch):
    monkeypatch.setattr(main, "run_scan", functools.partial(worker.run, timeout=0.001))
    body = scan(CASE["1-pdf-clean"], "unified").json()
    assert body["verdict"] == "UNABLE_TO_SCAN" and "timed out" in body["scanners"][0]["error"]


def test_real_worker_strict_isolation_for_the_unified_engine(research, monkeypatch):
    # Either every control is present and the scan runs, or the worker refuses to analyse.
    monkeypatch.setattr(worker, "REQUIRE_ISOLATION", True)
    report = asyncio.run(worker.run(CASE["5b-pdf-auto-js-exports-attachment"], engine="unified"))
    assert [s.name for s in report.scanners] == UNIFIED_SCANNERS
    if not worker.missing_controls(report.isolation):
        assert "ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT" in {f.rule_id for f in report.findings}
    else:
        assert all(s.status == "failed" and "required isolation unavailable" in s.error for s in report.scanners)
        assert report.findings == []


def test_engine_scanner_lists_match_the_engine():
    assert main.engine_scanners() == [s.name for s in unified_engine.SCANNERS] == UNIFIED_SCANNERS


def test_the_service_never_imports_a_retired_detection_dependency():
    # yara-x is development-only (signature parity tests); olevba's heuristics are not used either.
    import subprocess
    import sys
    code = ("import sys, app.main, app.worker, app.engine; from app import engine; "
            "app.worker.analyse(engine.SCANNERS, b'%PDF-1.7 /OpenAction /JavaScript'); "
            "assert 'yara_x' not in sys.modules, 'yara_x imported'")
    subprocess.run([sys.executable, "-c", code], check=True, cwd=Path(__file__).resolve().parent.parent)
    from app.engine import vba_analysis, vba_chains
    from app.scanners import office
    import ast
    for module in (vba_analysis, vba_chains, office):  # only the extractor is imported from olevba
        tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        imported = {(n.module, a.name) for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
        assert {name for mod, name in imported if mod == "oletools.olevba"} <= {"VBA_Parser"}, module
        calls = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        assert not calls & {"analyze_macros", "VBA_Scanner"}, module
