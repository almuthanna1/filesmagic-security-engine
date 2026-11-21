"""VBA analysis end to end on real (inert) VBA projects: oletools' real extractor decompresses
the source, then the Office scanner, vba-chains and correlation decide, in-process and through
the isolated worker. See tests/vba_fixtures.py: no P-code, placeholder arguments only.
"""

import pytest
from fastapi.testclient import TestClient

from app import engine, main, worker
from app.decision import decide
from app.engine import vba_analysis as va
from tests.office_fixtures import make_ole, word_document_stream
from tests.scan_client import auth_headers
from tests.vba_fixtures import docm, vba_project, vba_streams

client = TestClient(main.app)

AUTO_SHELL = {"Module1": 'Sub AutoOpen()\n    Module2.Helper\nEnd Sub\n',
              "Module2": 'Sub Helper()\n    Shell "placeholder"\nEnd Sub\n'}
UNRELATED = {"Module1": 'Sub AutoOpen()\n    MsgBox "hello"\nEnd Sub\n',
             "Module2": 'Sub Helper()\n    Shell "placeholder"\nEnd Sub\n'}
BENIGN = {"Module1": 'Sub FormatTable()\n    ActiveDocument.Tables(1).Style = "Grid"\nEnd Sub\n'}
HIDDEN = {"Module1": 'Sub Document_Open()\n    Set o = CreateObject(StrReverse("llehS.tpircSW"))\n'
                     '    o.Run "placeholder"\nEnd Sub\n'}


def run(data: bytes):
    report = engine.correlate(worker.analyse(engine.SCANNERS, data))
    ran = [s for s in report.scanners if s.status != "not_applicable"]
    failed = [s for s in ran if s.status == "failed"]
    return decide(report.findings, len(ran), len(failed)), {f.rule_id for f in report.findings}, report


def test_the_real_extractor_returns_vba_names_and_source():
    e = va.extract(vba_project(AUTO_SHELL), "vbaProject.bin")
    assert e.error is None and e.vba and [m for m, _ in e.modules] == ["Module1", "Module2"]
    assert 'Shell "placeholder"' in e.modules[1][1]


def test_qualified_call_from_an_entry_to_shell_is_malicious():
    verdict, rules, _ = run(docm(AUTO_SHELL))
    assert verdict == "MALICIOUS"
    assert {"ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY", "OFFICE_MACRO_AUTOEXEC_EXECUTION", "OOXML_VBA_Macros"} <= rules


def test_entry_and_capability_without_a_path_are_reported_not_hidden():
    verdict, rules, report = run(docm(UNRELATED))
    # The Office scanner's project-level rule still fires (HIGH); the call graph says no path, and
    # correlation keeps the finding (a source-only "no path" never lowers a verdict: P-code).
    assert verdict == "MALICIOUS" and "ENGINE_VBA_NO_CALL_PATH" in rules
    assert "OFFICE_MACRO_AUTOEXEC_EXECUTION" in rules


def test_a_harmless_macro_is_suspicious_never_safe():
    verdict, rules, _ = run(docm(BENIGN))
    assert verdict == "SUSPICIOUS" and "OFFICE_MACROS_PRESENT" in rules
    assert not rules & {"OFFICE_MACRO_AUTOEXEC_EXECUTION", "OFFICE_MACRO_DANGEROUS_CAPABILITY"}


def test_a_hidden_progid_is_decoded_and_resolved():
    verdict, rules, report = run(docm(HIDDEN))
    assert verdict == "MALICIOUS" and "OFFICE_MACRO_OBFUSCATION" in rules
    obfuscation = next(f for f in report.findings if f.rule_id == "OFFICE_MACRO_OBFUSCATION")
    assert "wscript.shell" in obfuscation.description.lower()


def test_legacy_doc_with_a_macros_storage():
    doc = make_ole({"WordDocument": word_document_stream(), **vba_streams(AUTO_SHELL, root="Macros/")})
    verdict, rules, _ = run(doc)
    assert verdict == "MALICIOUS" and "ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY" in rules


@pytest.mark.parametrize("modules, verdict", [(AUTO_SHELL, "MALICIOUS"), (BENIGN, "SUSPICIOUS")])
def test_through_the_isolated_worker(monkeypatch, modules, verdict):
    monkeypatch.setattr(main, "run_scan", worker.run)
    data = docm(modules)
    body = client.post("/scan", content=data, headers=auth_headers(data, "f.docm"), params={"engine": "unified"}).json()
    assert body["verdict"] == verdict and body["complete"]
