"""The refined PDF JavaScript signature (app.engine.signature_rules) on documents built to probe it.

The generic signature it refines (JavaScript plus any /OpenAction or /AA bytes) fires on every
variant below; the refined rule must stay silent only where the bytes prove the trigger is not
automatic. YARA-X parity for the same rule is in tests/test_signatures.py.
"""

import pytest

from app.engine.correlate import REFINED_SIGNATURE
from app.engine.signatures import SignatureScanner
from evaluation.cases import cases
from tests.pdf_fixtures import js_action, make_pdf

REFINED = SignatureScanner()
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
    # A regex match is at most MAX_REGEX_MATCH (4095) bytes, as in YARA-X: a longer /AA dictionary is not proven.
    "user-only /AA with a 4,000-byte script": (widget("<< /K << /S /JavaScript /JS (" + "a" * 4000 + ") >> >>"), False),
    "user-only /AA with a 5,000-byte script (beyond the regex limit)": (
        widget("<< /K << /S /JavaScript /JS (" + "a" * 5000 + ") >> >>"), True),
}



def generic(data: bytes) -> bool:
    """The superseded generic signature's condition (tests/signature_parity/reference.yar)."""
    return (data.find(b"%PDF-", 0, 1029) >= 0 and (b"/JS" in data or b"/JavaScript" in data)
            and (b"/OpenAction" in data or b"/AA" in data))


def fires(data: bytes) -> bool:
    return any(f.rule_id == REFINED_SIGNATURE[1] for f in REFINED.scan("", data))


@pytest.mark.parametrize("name", VARIANTS)
def test_refined_rule_discounts_only_triggers_its_bytes_prove_non_automatic(name):
    data, expected = VARIANTS[name]
    assert generic(data)  # every variant is a generic match
    assert fires(data) == expected


@pytest.mark.parametrize("data", [d for d, _ in VARIANTS.values()] + [c["data"] for c in cases()])
def test_refined_rule_never_fires_where_the_generic_rule_does_not(data):
    assert not fires(data) or generic(data)
