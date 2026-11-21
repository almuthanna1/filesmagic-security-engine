"""FilesMagic signature matcher (app.engine.signatures) and its rules.

Inputs are tiny synthetic byte strings holding only the structural markers a rule looks for;
none is malware or a functional document. Where the yara-x package is installed (development:
requirements-dev.txt), every rule is also checked against YARA-X running the original rule
text (tests/signature_parity/*.yar), on fixtures, the benign corpus and seeded random inputs.
"""

import random
import time
from pathlib import Path

import pytest

from app.engine import signatures as sig
from app.engine.signature_rules import RULES
from app.engine.signatures import Matches, Rule, SignatureError, SignatureScanner, find_all, literal, regex
from app.models import Severity
from evaluation.cases import cases
from tests.pdf_fixtures import js_action, make_pdf

ROOT = Path(__file__).resolve().parent.parent
OLE_MAGIC = bytes.fromhex("D0CF11E0A1B11AE1")
PE_STUB = b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0"
SCANNER = SignatureScanner()
REFINED = "ENGINE_PDF_JavaScript_With_Automatic_Trigger"


def rules_for(data: bytes, scanner: SignatureScanner = SCANNER) -> set[str]:
    return {f.rule_id for f in scanner.scan("", data)}


def offsets(data: bytes, pattern) -> list[int]:
    return find_all(data, pattern.compiled())


# ----------------------------------------------------------------------------- matching primitives


def test_matches_overlap_and_are_identified_by_start_offset():
    assert offsets(b"aaaa", literal(b"aa")) == [0, 1, 2]
    assert offsets(b"aaaz", regex(rb"a[^z]*z")) == [0, 1, 2]  # re.finditer would report one
    assert offsets(b"/OpenAction/OpenAction ", regex(rb"/OpenAction[ /]", prefix=b"/OpenAction")) == [0, 11]


def test_nocase_is_ascii_case_folding_and_wide_is_utf16le_only():
    assert offsets(b"x DdEaUtO y", literal(b"DDEAUTO", nocase=True)) == [2]
    wide = "_VBA_PROJECT".encode("utf-16-le")
    assert offsets(b"..." + wide, literal(b"_VBA_PROJECT", wide=True)) == [3]
    assert offsets(b"_VBA_PROJECT", literal(b"_VBA_PROJECT", wide=True)) == []  # plain form is not wide


def test_offset_ranges_are_inclusive_like_yara_in():
    m = lambda data: Matches(data, {"p": literal(b"%PDF-").compiled()}, {}, time.monotonic() + 9)  # noqa: E731
    assert m(b" " * 1024 + b"%PDF-").within("p", 0, 1024)
    assert not m(b" " * 1025 + b"%PDF-").within("p", 0, 1024)


def test_integers_outside_the_file_are_undefined_not_zero():
    m = Matches(b"MZ", {}, {}, time.monotonic() + 9)
    assert m.u16(0) == 0x5A4D and m.u32(0) is None and m.u32(-1) is None
    assert "Native_Executable" not in rules_for(b"MZ" + b"\0" * 58 + (10**6).to_bytes(4, "little"))


def test_match_counts_saturate_at_the_cap():
    assert len(offsets(b"/AA " * 5000, regex(rb"/AA ", prefix=b"/AA"))) == sig.MAX_MATCHES_PER_PATTERN


@pytest.mark.parametrize("length, found", [(sig.MAX_REGEX_MATCH, True), (sig.MAX_REGEX_MATCH + 1, False)])
def test_a_regex_match_is_at_most_the_window_long(length, found):
    data = b"ab" + b"c" * (length - 3) + b"z"
    assert len(data) == length
    for p in (regex(rb"ab[^z]*z"), regex(rb"ab[^z]*z", prefix=b"ab")):
        assert bool(offsets(data, p)) == found


def test_a_long_match_does_not_hide_a_later_start_that_fits():
    data = b"ab" + b"c" * 5000 + b"ab" + b"cz"
    assert offsets(data, regex(rb"ab[^z]*z")) == [5002]


# ----------------------------------------------------------------------------- rules


TRIGGERS = [
    (b"%PDF-1.7\n1 0 obj << /S /Launch /F (x) >>", "PDF_Launch_Action", Severity.HIGH),
    (b"%PDF-1.7\n<< /OpenAction 2 0 R >> << /S /JavaScript /JS (x) >>", REFINED, Severity.MEDIUM),
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
    b"", b"hello world",
    b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >>\n%%EOF",
    b"PK\x03\x04" + b"\0" * 26 + b"word/document.xml",
    OLE_MAGIC + b"\0" * 64 + "WordDocument".encode("utf-16-le"),
    b"{\\rtf1 plain text}",
    b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1" height="1"/></svg>',
    b"MZ but not a PE file",
    b"not a pdf /Launch /EmbeddedFile",  # markers without the header: the rule does not apply
    b" " * 1100 + b"%PDF-1.7 /Launch",  # header beyond the first 1024 bytes
]


@pytest.mark.parametrize("data, rule, severity", TRIGGERS, ids=[f"{t[1]}-{i}" for i, t in enumerate(TRIGGERS)])
def test_each_rule_fires_on_its_marker_with_its_metadata(data, rule, severity):
    found = {f.rule_id: f for f in SCANNER.scan("", data)}
    assert rule in found and found[rule].severity == severity and found[rule].scanner == "signatures"
    assert found[rule].evidence  # where the patterns matched


@pytest.mark.parametrize("data", BENIGN, ids=range(len(BENIGN)))
def test_benign_inputs_match_nothing(data):
    assert rules_for(data) == set()


def test_evidence_lists_offsets_never_content():
    f = next(f for f in SCANNER.scan("", b"%PDF-1.7 /Launch secret") if f.rule_id == "PDF_Launch_Action")
    assert f.evidence == ["$pdf: 1 match(es) at offset 0x0", "$launch: 1 match(es) at offset 0x9"]
    assert not any("secret" in e for e in f.evidence)


def test_results_are_deterministic():
    data = TRIGGERS[1][0] + TRIGGERS[0][0]
    assert all(SCANNER.scan("", data) == SCANNER.scan("", data) for _ in range(5))


# ----------------------------------------------------------------------------- fail closed


@pytest.mark.parametrize("rules", [
    [Rule("bad id", "d", "c", Severity.LOW, {}, lambda m: True)],
    [Rule("R", "", "c", Severity.LOW, {}, lambda m: True)],
    [Rule("R", "d", "Not Kebab", Severity.LOW, {}, lambda m: True)],
    [Rule("R", "d", "c", "LOW", {}, lambda m: True)],
    [Rule("R", "d", "c", Severity.LOW, {"p": regex(rb"(unclosed")}, lambda m: True)],
    [Rule("R", "d", "c", Severity.LOW, {"p": regex(rb"/AA", prefix=b"/OpenAction")}, lambda m: True)],
    [Rule("R", "d", "c", Severity.LOW, {}, lambda m: True)] * 2,  # duplicate id
])
def test_invalid_rules_make_the_scanner_not_ready_and_every_scan_fail(rules):
    s = SignatureScanner(rules)
    assert not s.ready and s.error
    with pytest.raises(SignatureError, match="not ready"):
        s.scan("", b"x")


def test_a_condition_that_raises_fails_the_scan():
    s = SignatureScanner([Rule("R", "d", "c", Severity.LOW, {"p": literal(b"x")}, lambda m: m.count("nope"))])
    with pytest.raises(SignatureError, match="could not be evaluated"):
        s.scan("", b"x")


def test_the_deadline_fails_the_scan_instead_of_passing(monkeypatch):
    monkeypatch.setattr(sig, "SCAN_TIMEOUT_SECONDS", -1)
    with pytest.raises(SignatureError, match="exceeded"):
        SCANNER.scan("", b"%PDF-1.7 /Launch")


@pytest.mark.parametrize("data", [
    b"%PDF-1.7 /JS " + b"/AA<<" * 400_000,
    b"%PDF-1.7 /JS /AA<< /K <<" + b"a" * 3_000_000 + b"/AA<< /K <<" * 50_000,
    b"%PDF-1.7 /JS " + b"/AA << /K 1 0 R /F 1 0 R " * 100_000,
    b"<svg " + b" onload" * 300_000 + b" " * 1_000_000,
], ids=["aa-open-dicts", "long-flat-dict", "user-keys", "svg-handlers"])
def test_adversarial_inputs_stay_bounded(data):
    start = time.perf_counter()
    SCANNER.scan("", data)
    assert time.perf_counter() - start < 5


# ----------------------------------------------------------------------------- parity with YARA-X


def fuzz_inputs(n: int = 3000, seed: int = 499) -> list[bytes]:
    rng = random.Random(seed)
    parts = [b"%PDF-1.7\n", b"/OpenAction", b"/OpenAction [3 0 R /Fit]", b"/OpenAction 5 0 R", b"/AA", b"/AAx",
             b"/AA << /K 5 0 R >>", b"/AA<</K<</S/JavaScript/JS(x)>>>>", b"/AA << /O 5 0 R >>",
             b"/AA << /K << /JS <ab> >> /F 6 0 R >>", b"/AA << /PV 6 0 R >>", b"/JS", b"/JavaScript", b"/Launch",
             b"/EmbeddedFile", b"/EmbeddedFiles", b" ", b"\n", b"\x00", b"<<", b">>", b"[", b"(", b")", b"/", b"%",
             b"{\\rtf1", b"\\object", b"\\OBJUPDATE", b"ddeauto", b"<svg", b"<SCRIPT", b" onLoad =", b"\tonbegin=",
             b"javascript:", b"PK\x03\x04", b"vbaProject.bin", OLE_MAGIC, "_VBA_PROJECT".encode("utf-16-le"),
             b"MZ", b"PE\0\0", b"\x7fELF", b"a" * 50, b"0 0 R", b"<ab>"]
    out = []
    for _ in range(n):
        out.append(b"".join(rng.choice(parts) for _ in range(rng.randint(1, 14))))
    # Headers at fixed offsets, so the u16/u32 checks and offset ranges are exercised.
    out += [b"{\\rtf1 " + a + b for a in parts for b in parts] + [b"MZ" + bytes(rng.randrange(256) for _ in range(70)) for _ in range(200)]
    out += [b" " * k + b"%PDF-1.7 /Launch" for k in (1019, 1020, 1024, 1025)]
    out += [b"<svg " + b" " * k + b"onload=" for k in (4080, 4090, 4100)]
    out += [b"%PDF-1.7 /JS /AA << /K << /JS (" + b"a" * k + b") >> >>" for k in range(4000, 4100, 7)]
    return out


def parity_corpus() -> list[bytes]:
    from tests.test_engine_signatures import VARIANTS

    corpus = [d for d, *_ in TRIGGERS] + BENIGN + [d for d, _ in VARIANTS.values()] + [c["data"] for c in cases()]
    for folder in ("files", "independent"):
        corpus += [p.read_bytes() for p in sorted((ROOT / "evaluation/benign_corpus" / folder).iterdir())
                   if p.suffix != ".json"]
    return corpus + fuzz_inputs()


@pytest.fixture(scope="module")
def yara():
    yara_x = pytest.importorskip("yara_x", reason="parity needs the yara-x package (requirements-dev.txt)")
    compiler = yara_x.Compiler(includes_enabled=False)
    for path in sorted((ROOT / "tests/signature_parity").glob("*.yar")):
        compiler.add_source(path.read_text(encoding="utf-8"), origin=path.name)
    rules = compiler.build()

    def scan(data: bytes) -> set[str]:
        s = yara_x.Scanner(rules)
        s.max_matches_per_pattern(sig.MAX_MATCHES_PER_PATTERN)
        # Not ported: the engine always replaced it by the refined rule (signature_rules docstring).
        return {r.identifier for r in s.scan(data).matching_rules} - {"PDF_JavaScript_With_Automatic_Action"}
    return scan


def test_every_ported_rule_agrees_with_yara_x(yara):
    corpus = parity_corpus()
    disagreements = [(i, sorted(yara(d) ^ rules_for(d))) for i, d in enumerate(corpus) if yara(d) != rules_for(d)]
    assert not disagreements, disagreements[:10]
    fired = set().union(*(rules_for(d) for d in corpus))
    assert fired == {r.id for r in RULES}  # every rule was exercised positively, not only negatively


def test_the_ported_rules_are_exactly_the_yara_rules_minus_the_superseded_one(yara):
    text = "".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests/signature_parity").glob("*.yar"))
    import re
    yara_ids = set(re.findall(r"^rule (\w+)", text, re.M)) - {"PDF_JavaScript_With_Automatic_Action"}
    assert yara_ids == {r.id for r in RULES}


def test_refined_rule_never_fires_where_the_superseded_generic_rule_would_not():
    # The superseded rule's own condition, from its YARA text: header, any JS, any /OpenAction or /AA.
    generic = lambda d: (d.find(b"%PDF-", 0, 1029) >= 0 and (b"/JS" in d or b"/JavaScript" in d) and (b"/OpenAction" in d or b"/AA" in d))  # noqa: E731
    assert all(generic(d) for d in parity_corpus() if REFINED in rules_for(d))


# ----------------------------------------------------------------------------- ported from test_yarax.py
# (the YARA-X scanner was retired; these behaviours of it must hold for its replacement)


def test_pdf_header_after_leading_junk_is_still_detected():
    assert [f.rule_id for f in SCANNER.scan("f", b"junk" * 100 + b"%PDF-1.7 /Launch")] == ["PDF_Launch_Action"]


def test_large_clean_input_and_many_repeated_matches():
    assert SCANNER.scan("f", b"\0" * (10 * 1024 * 1024)) == []
    data = b"%PDF-1.7 " + b"/Launch " * 100_000  # far more matches than the cap
    assert [f.rule_id for f in SCANNER.scan("f", data)] == ["PDF_Launch_Action"]


def test_api_verdicts_and_readiness(monkeypatch):
    from fastapi.testclient import TestClient

    from app import main
    from app.models import Verdict
    from tests.scan_client import post_scan

    client = TestClient(main.app)
    broken = SignatureScanner([Rule("bad id", "x", "pdf", Severity.HIGH, {}, lambda m: True)])

    def verdict(data, scanner=SCANNER):
        monkeypatch.setattr(main.unified_engine, "SCANNERS", [scanner])
        return post_scan(client, data, "f.bin").json()["verdict"]

    assert verdict(b"hello world") == Verdict.SAFE
    assert verdict(b"%PDF-1.7 /Launch") == Verdict.MALICIOUS
    assert verdict(b"\x7fELF") == Verdict.SUSPICIOUS
    assert verdict(b"hello", broken) == Verdict.UNABLE_TO_SCAN
    monkeypatch.setattr(main.unified_engine, "SCANNERS", [SCANNER, broken])
    health = client.get("/health").json()
    assert (health["scanners_registered"], health["scanners_ready"]) == (2, 1)
