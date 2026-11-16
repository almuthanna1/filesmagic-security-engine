"""The engine's refined YARA-X rule (app/engine/rules/pdf.yar) against the reference rule."""

import pytest

from app import engine
from app.engine.correlate import REFERENCE_SIGNATURE, REFINED_SIGNATURE, correlate
from app.models import Finding, ScannerStatus, Severity, WorkerReport
from app.scanners.yarax import YaraXScanner
from evaluation.cases import cases
from tests.pdf_fixtures import js_action, make_pdf

REFERENCE, REFINED = YaraXScanner(), engine.EngineSignatures()
WIDGET = "<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /Rect [0 0 1 1] /AA {} >>"


def widget(aa: str, objects: dict | None = None) -> bytes:
    return make_pdf(page_extra="/Annots [5 0 R]", objects={5: WIDGET.format(aa), **(objects or {})})


# (document, does the refined rule fire?)
VARIANTS = {
    "user-only /AA, direct": (widget("<< /K << /S /JavaScript /JS (AFNumber_Keystroke\\(2\\);) >> >>"), False),
    "user-only /AA, keys by reference": (widget("<< /K 6 0 R /F 6 0 R /V 6 0 R /C 6 0 R >>", {6: js_action()}), False),
    "page destination only": (make_pdf(catalog_extra="/OpenAction [3 0 R /Fit]", objects={5: js_action()}), False),
    "automatic /AA /PO": (widget("<< /PO << /S /JavaScript /JS (x) >> >>"), True),
    "user and automatic keys mixed": (widget("<< /K 6 0 R /PV 6 0 R >>", {6: js_action()}), True),
    "indirect /AA (not provable from bytes)": (widget("6 0 R", {6: "<< /K 7 0 R >>", 7: js_action()}), True),
    "'>' inside the script (not provable)": (widget("<< /K << /S /JavaScript /JS (if \\(a > b\\) x;) >> >>"), True),
    "indirect /OpenAction to a destination (not provable)": (
        make_pdf(catalog_extra="/OpenAction 6 0 R", objects={5: js_action(), 6: "[3 0 R /Fit]"}), True),
    "page destination plus page-open /AA /O": (
        make_pdf(catalog_extra="/OpenAction [3 0 R /Fit]", page_extra="/AA << /O 5 0 R >>", objects={5: js_action()}), True),
    # Measured: YARA-X ends a regex match at about 4 KiB, so a longer /AA dictionary is not proven.
    "user-only /AA with a 4,000-byte script": (widget("<< /K << /S /JavaScript /JS (" + "a" * 4000 + ") >> >>"), False),
    "user-only /AA with a 5,000-byte script (beyond the regex limit)": (
        widget("<< /K << /S /JavaScript /JS (" + "a" * 5000 + ") >> >>"), True),
}


def fires(scanner, data: bytes, rule: str) -> bool:
    return any(f.rule_id == rule for f in scanner.scan("", data))


@pytest.mark.parametrize("name", VARIANTS)
def test_refined_rule_discounts_only_triggers_its_bytes_prove_non_automatic(name):
    data, expected = VARIANTS[name]
    assert fires(REFERENCE, data, REFERENCE_SIGNATURE[1])  # every variant is a reference match
    assert fires(REFINED, data, REFINED_SIGNATURE[1]) == expected


@pytest.mark.parametrize("data", [d for d, _ in VARIANTS.values()] + [c["data"] for c in cases()])
def test_refined_rule_never_fires_where_the_reference_rule_does_not(data):
    assert not fires(REFINED, data, REFINED_SIGNATURE[1]) or fires(REFERENCE, data, REFERENCE_SIGNATURE[1])


def report(engine_status: str) -> WorkerReport:
    match = Finding(scanner="yara-x", category="pdf-active-content", severity=Severity.MEDIUM, description="x",
                    rule_id=REFERENCE_SIGNATURE[1])
    return WorkerReport(scanners=[ScannerStatus(name="yara-x", status="completed"),
                                  ScannerStatus(name="yara-x-engine", status=engine_status)], findings=[match])


def test_reference_match_is_replaced_only_when_the_refined_rules_ran():
    assert correlate(report("failed")) == report("failed")
    replaced = correlate(report("completed"))
    assert [f.rule_id for f in replaced.findings] == ["ENGINE_CORRELATION"]
    assert "did not match" in replaced.findings[0].description
