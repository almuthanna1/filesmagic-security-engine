"""YARA-X scanner tests.

Uses the real yara-x engine with the repository rules. Test inputs are tiny synthetic
byte strings containing only the structural markers a rule looks for (e.g. "%PDF-"
and "/Launch"); none of them is malware or a functional document.
"""

import pytest
from fastapi.testclient import TestClient

from app import main
from app.models import Severity, Verdict
from app.scanners import yarax
from app.scanners.yarax import YaraXError, YaraXScanner

OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
PE_STUB = b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0"

# (synthetic input, expected rule, expected severity)
TRIGGERS = [
    (b"%PDF-1.7\n1 0 obj << /S /Launch /F (x) >>", "PDF_Launch_Action", Severity.HIGH),
    (b"%PDF-1.7\n<< /OpenAction 2 0 R >> << /S /JavaScript /JS (x) >>", "PDF_JavaScript_With_Automatic_Action", Severity.MEDIUM),
    (b"%PDF-1.7\n<< /Type /EmbeddedFile >>", "PDF_Embedded_File", Severity.LOW),
    (OLE_MAGIC + b"\0" * 64 + "_VBA_PROJECT".encode("utf-16-le"), "OLE_Office_VBA_Macros", Severity.MEDIUM),
    (b"PK\x03\x04" + b"\0" * 26 + b"word/vbaProject.bin", "OOXML_VBA_Macros", Severity.MEDIUM),
    (b"{\\rtf1 {\\object\\objemb\\objupdate {\\*\\objdata 00}}}", "RTF_Auto_Updating_Embedded_Object", Severity.HIGH),
    (b'{\\rtf1 {\\field{\\*\\fldinst DDEAUTO "x" "y"}}}', "RTF_DDE_Auto_Field", Severity.MEDIUM),
    (b'<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>', "SVG_Script_Content", Severity.MEDIUM),
    (b'<svg xmlns="http://www.w3.org/2000/svg" onload="x()"></svg>', "SVG_Script_Content", Severity.MEDIUM),
    (PE_STUB, "Native_Executable", Severity.MEDIUM),
    (b"\x7fELF\x02\x01\x01", "Native_Executable", Severity.MEDIUM),
]

BENIGN = [
    b"hello world",
    b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >>\n%%EOF",
    b"PK\x03\x04" + b"\0" * 26 + b"word/document.xml",
    OLE_MAGIC + b"\0" * 64 + "WordDocument".encode("utf-16-le"),
    b"{\\rtf1 plain text}",
    b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>',
    b"MZ but not a PE file",
]


@pytest.fixture(scope="module")
def scanner():
    s = YaraXScanner()
    assert s.ready, s.error
    return s


def write_rules(tmp_path, source):
    (tmp_path / "rules.yar").write_text(source, encoding="utf-8")
    return tmp_path


# Rules and matching


@pytest.mark.parametrize("data, rule_id, severity", TRIGGERS)
def test_rule_triggers(scanner, data, rule_id, severity):
    findings = scanner.scan("f", data)
    assert [f.rule_id for f in findings] == [rule_id]
    [f] = findings
    assert f.scanner == "yara-x"
    assert f.severity == severity
    assert f.category and f.description


@pytest.mark.parametrize("data", BENIGN)
def test_benign_inputs_have_no_findings(scanner, data):
    assert scanner.scan("f", data) == []


def test_pdf_header_after_leading_junk_is_still_detected(scanner):
    data = b"junk" * 100 + b"%PDF-1.7 /Launch"
    assert [f.rule_id for f in scanner.scan("f", data)] == ["PDF_Launch_Action"]


def test_large_clean_input(scanner):
    assert scanner.scan("f", b"\0" * (10 * 1024 * 1024)) == []


def test_many_repeated_matches_still_detected_with_match_cap(scanner):
    data = b"%PDF-1.7 " + b"/Launch " * 100_000  # far more matches than the cap
    assert [f.rule_id for f in scanner.scan("f", data)] == ["PDF_Launch_Action"]


# Failure modes: each must raise so the scan is UNABLE_TO_SCAN, never SAFE


def test_syntax_error_makes_scanner_not_ready(tmp_path):
    s = YaraXScanner(write_rules(tmp_path, "rule broken {"))
    assert not s.ready and "CompileError" in s.error
    with pytest.raises(YaraXError, match="not ready"):
        s.scan("f", b"x")


@pytest.mark.parametrize(
    "meta",
    [
        'category = "x" severity = "HIGH"',  # no description
        'description = "x" severity = "HIGH"',  # no category
        'description = "x" category = "x"',  # no severity
        'description = "x" category = "x" severity = "SEVERE"',  # invalid severity
        'description = "x" category = "Not Kebab" severity = "LOW"',  # invalid category
    ],
)
def test_rule_metadata_is_enforced_at_compile_time(tmp_path, meta):
    s = YaraXScanner(write_rules(tmp_path, f"rule r {{ meta: {meta} condition: true }}"))
    assert not s.ready


def test_valid_custom_rule_compiles(tmp_path):
    s = YaraXScanner(write_rules(tmp_path, 'rule r { meta: description = "d" category = "c" severity = "LOW" condition: true }'))
    assert s.ready
    assert [f.severity for f in s.scan("f", b"x")] == [Severity.LOW]


def test_no_rule_files_makes_scanner_not_ready(tmp_path):
    s = YaraXScanner(tmp_path)
    assert not s.ready and "no .yar rule files" in s.error


def test_missing_yara_x_package_makes_scanner_not_ready(monkeypatch):
    monkeypatch.setattr(yarax, "yara_x", None)
    s = YaraXScanner()
    assert not s.ready and "not installed" in s.error


class FakeScanner:
    def __init__(self, rules, raises=None, matching_rules=()):
        self.raises, self.matching_rules = raises, matching_rules

    def set_timeout(self, seconds):
        self.timeout = seconds

    def max_matches_per_pattern(self, matches):
        self.max_matches = matches

    def scan(self, data):
        if self.raises:
            raise self.raises
        return type("Results", (), {"matching_rules": self.matching_rules})()


def use_fake_scanner(monkeypatch, **kwargs):
    monkeypatch.setattr(yarax.yara_x, "Scanner", lambda rules: FakeScanner(rules, **kwargs))


def test_timeout_raises(monkeypatch, scanner):
    use_fake_scanner(monkeypatch, raises=yarax.yara_x.TimeoutError("timeout"))
    with pytest.raises(YaraXError, match="timed out"):
        scanner.scan("f", b"x")


def test_scan_error_raises(monkeypatch, scanner):
    use_fake_scanner(monkeypatch, raises=yarax.yara_x.ScanError("boom"))
    with pytest.raises(YaraXError, match="scan failed"):
        scanner.scan("f", b"x")


def test_match_with_unusable_metadata_fails_closed(monkeypatch, scanner):
    rule = type("Rule", (), {"identifier": "odd", "metadata": (("severity", "HIGH"),)})()
    use_fake_scanner(monkeypatch, matching_rules=(rule,))
    with pytest.raises(YaraXError, match="unusable metadata"):
        scanner.scan("f", b"x")


# End to end through the API with YARA-X as the only scanner

client = TestClient(main.app)


def verdict_for(monkeypatch, data, scanner=None):
    monkeypatch.setattr(main, "SCANNERS", [scanner or YaraXScanner()])
    r = client.post("/scan", files={"file": ("f.bin", data)})
    assert r.status_code == 200
    return r.json()


def test_api_clean_file_is_safe(monkeypatch):
    body = verdict_for(monkeypatch, b"hello world")
    assert body["verdict"] == Verdict.SAFE and body["findings"] == []
    assert "not a guarantee" in body["message"]


def test_api_high_finding_is_malicious(monkeypatch):
    body = verdict_for(monkeypatch, b"%PDF-1.7 /Launch")
    assert body["verdict"] == Verdict.MALICIOUS
    assert body["findings"][0]["rule_id"] == "PDF_Launch_Action"


def test_api_medium_finding_is_suspicious(monkeypatch):
    assert verdict_for(monkeypatch, b"\x7fELF")["verdict"] == Verdict.SUSPICIOUS


def test_api_not_ready_scanner_is_unable_to_scan(monkeypatch, tmp_path):
    body = verdict_for(monkeypatch, b"hello", YaraXScanner(write_rules(tmp_path, "rule broken {")))
    assert body["verdict"] == Verdict.UNABLE_TO_SCAN and body["findings"] == []


def test_health_reports_readiness(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "SCANNERS", [YaraXScanner(), YaraXScanner(write_rules(tmp_path, "rule broken {"))])
    body = client.get("/health").json()
    assert body["scanners_registered"] == 2
    assert body["scanners_ready"] == 1
