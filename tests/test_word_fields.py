"""C7 Word field codes on inert packages, built in memory and never written to disk. Every host is
an RFC 2606 .invalid name; every command is `rem inert` (a comment that does nothing); nothing is
evaluated, updated or fetched."""

import asyncio
import pytest

from app import engine, worker
from app.engine import word_fields as wf
from app.engine.word_fields import NESTED, Field, classify, fields, tokens
from app.scanners import SCANNERS
from evaluation.cases import cases, verdicts
from tests import custom_fixtures as fx

W, STRICT_W = fx.W, "http://purl.oclc.org/ooxml/wordprocessingml/main"
WEB = "https://example.invalid"
CMD = r'DDEAUTO c:\\windows\\system32\\cmd.exe "/c rem inert"'  # as Word stores it: \\ for one backslash


simple, complex_field, run, document, docx = fx.simple_field, fx.complex_field, fx.field_run, fx.word_document, fx.field_docx
BEGIN, SEPARATE, END = fx.FIELD_BEGIN, fx.FIELD_SEPARATE, fx.FIELD_END


def rules(data: bytes) -> list[tuple[str, str]]:
    return sorted((f.rule_id, f.severity.value) for f in wf.findings(wf.scan(data)))


# ----------------------------------------------------------------------------- reading the XML

def test_simple_and_complex_fields_are_read_with_split_runs_and_without_the_result():
    found = fields(document(simple("PAGE") + complex_field("DDE", "AUTO cmd ", '"/c rem inert"', result="DDE x"))
                   .encode(), "word/document.xml")
    assert [f.instruction for f in found] == ["PAGE", 'DDEAUTO cmd "/c rem inert"']


def test_a_nested_field_leaves_a_placeholder_in_the_outer_instruction():
    inner = (f'{BEGIN}{run("<w:instrText>QUOTE 99 109 100</w:instrText>")}'
             f'{END}')
    outer = (f'<w:p>{BEGIN}{run("<w:instrText>DDEAUTO </w:instrText>")}{inner}'
             f'{run("<w:instrText> x</w:instrText>")}{END}</w:p>')
    found = fields(document(outer).encode())
    assert [f.instruction for f in found] == ["QUOTE 99 109 100", f"DDEAUTO {NESTED} x"]
    assert classify(found[1])[0] == "ENGINE_WORD_DDEAUTO_PROGRAM"


def test_tracked_deletions_unterminated_fields_and_strict_namespace_are_read():
    deleted = fields(document(complex_field(("DDE cmd x", "del"))).encode())
    assert deleted == [Field("", "", deleted="DDE cmd x")]  # nothing live
    unterminated = f'<w:p>{BEGIN}{run("<w:instrText>DDE cmd x</w:instrText>")}</w:p>'
    assert [f.instruction for f in fields(document(unterminated).encode())] == ["DDE cmd x"]
    assert [f.instruction for f in fields(document(simple("DDE cmd x"), ns=STRICT_W).encode())] == ["DDE cmd x"]


def test_elements_with_the_same_names_in_another_namespace_are_not_fields():
    assert fields(document(simple("DDE cmd x"), ns="urn:example:not-word").encode()) == []


# ----------------------------------------------------------------------------- tracked changes
# A deletion records removed content: it is evidence of what the document contained, not that
# Word evaluates it. Only live text is classified; deleted text gives INFO only.

DELETED_RULE = "ENGINE_WORD_DELETED_INSTRUCTION"


@pytest.mark.parametrize("body", [
    complex_field(("DDEAUTO cmd x", "del")),  # w:delInstrText inside w:del, as Word writes it
    complex_field(("DDEAUTO cmd x", "del", "instrText")),  # plain w:instrText inside w:del
    complex_field(("DDEAUTO cmd x", "moveFrom")),  # the source of a tracked move
    complex_field(("DDEAUTO cmd x", "ins", "delInstrText")),  # w:delInstrText alone marks it removed
    f'<w:p><w:del {fx.REVISION.format(9)}>{fx.field_runs("DDEAUTO cmd x")}</w:del></w:p>',  # the whole field deleted
])
def test_instructions_only_in_tracked_deletions_are_recorded_without_an_execution_claim(body):
    found = wf.findings(wf.scan(docx(body)))
    assert [(f.rule_id, f.severity.value) for f in found] == [(DELETED_RULE, "INFO")]
    assert "with the tracked deletion rejected: ENGINE_WORD_DDEAUTO_PROGRAM" in found[0].evidence[0]
    assert "not that Word evaluates it" in found[0].description


def test_live_text_is_classified_and_a_deletion_that_would_change_it_is_noted():
    # live "DDE cmd x"; with "AUTO" restored it would read "DDEAUTO cmd x"
    assert rules(docx(complex_field("DDE", ("AUTO", "del"), " cmd x"))) == [
        ("ENGINE_WORD_DDE_PROGRAM", "MEDIUM"), (DELETED_RULE, "INFO")]
    # a deleted space joins the live text into DDEAUTO: the live text stands
    assert rules(docx(complex_field("DDE", (" ", "del"), "AUTO cmd x"))) == [
        ("ENGINE_WORD_DDEAUTO_PROGRAM", "HIGH"), (DELETED_RULE, "INFO")]
    # inserted (pending) text is live
    assert rules(docx(complex_field(("DDEAUTO cmd x", "ins")))) == [("ENGINE_WORD_DDEAUTO_PROGRAM", "HIGH")]


def test_deletions_that_change_nothing_reportable_give_nothing():
    assert rules(docx(complex_field(("PAGE", "del")))) == []
    assert rules(docx(complex_field("DDEAUTO cmd x", (" y", "del")))) == [("ENGINE_WORD_DDEAUTO_PROGRAM", "HIGH")]


# ----------------------------------------------------------------------------- instruction syntax

@pytest.mark.parametrize("instruction, expected", [
    (CMD, ["DDEAUTO", r"c:\windows\system32\cmd.exe", "/c rem inert"]),
    (r'INCLUDEPICTURE "https://example.invalid/p.png" \* MERGEFORMATINET', ["INCLUDEPICTURE", "https://example.invalid/p.png"]),
    (r'INCLUDETEXT "\\\\server.invalid\\share\\a.docx" \c Word', ["INCLUDETEXT", r"\\server.invalid\share\a.docx"]),
    (r'INCLUDETEXT \\\\server.invalid\\a.docx', ["INCLUDETEXT", r"\\server.invalid\a.docx"]),  # unquoted, still text
    (r'QUOTE "say \"hi\""', ["QUOTE", 'say "hi"']),
    ("  page  ", ["page"]),
    ("", []),
])
def test_tokens_unescape_and_stop_at_the_first_switch(instruction, expected):
    assert tokens(instruction) == expected


# ----------------------------------------------------------------------------- classification

@pytest.mark.parametrize("instruction, rule", [
    (CMD, "ENGINE_WORD_DDEAUTO_PROGRAM"),
    ('DDEAUTO cmd "/c rem inert"', "ENGINE_WORD_DDEAUTO_PROGRAM"),
    ("ddeauto PowerShell.exe x", "ENGINE_WORD_DDEAUTO_PROGRAM"),
    ("DDEAUTO mshta x", "ENGINE_WORD_DDEAUTO_PROGRAM"),
    (r"DDEAUTO C:\\inert\\tool x", "ENGINE_WORD_DDEAUTO_PROGRAM"),  # a path, whatever the name
    (f"DDEAUTO {NESTED} x", "ENGINE_WORD_DDEAUTO_PROGRAM"),
    ('DDE cmd "/c rem inert"', "ENGINE_WORD_DDE_PROGRAM"),
    (r'DDEAUTO Excel "C:\\inert\\book.xlsx" "Sheet1!R1C1"', "ENGINE_WORD_DDE_APPLICATION"),
    ("DDE Excel Sheet1 R1C1", "ENGINE_WORD_DDE_APPLICATION"),
    ("DDEAUTO", "ENGINE_WORD_DDE_APPLICATION"),  # names nothing
    (f'INCLUDETEXT "{WEB}/a.docx"', "ENGINE_WORD_REMOTE_INCLUDE"),
    (r'INCLUDETEXT "\\\\server.invalid\\share\\a.docx"', "ENGINE_WORD_REMOTE_INCLUDE"),
    ('INCLUDETEXT "file://server.invalid/share/a.docx"', "ENGINE_WORD_REMOTE_INCLUDE"),
    ('INCLUDETEXT "//server.invalid/share/a.docx"', "ENGINE_WORD_REMOTE_INCLUDE"),
    (f"INCLUDETEXT {NESTED}", "ENGINE_WORD_REMOTE_INCLUDE"),
    (f'INCLUDE "{WEB}/a.docx"', "ENGINE_WORD_REMOTE_INCLUDE"),  # the old name
    (r'INCLUDETEXT "C:\\docs\\a.docx" Part1', "ENGINE_WORD_LOCAL_INCLUDE"),
    ('INCLUDETEXT "file:///C:/docs/a.docx"', "ENGINE_WORD_LOCAL_INCLUDE"),
    ('INCLUDETEXT "chapter2.docx"', "ENGINE_WORD_LOCAL_INCLUDE"),
    (rf'INCLUDEPICTURE "{WEB}/p.png" \* MERGEFORMATINET', "ENGINE_WORD_WEB_PICTURE"),
    (f'IMPORT "{WEB}/p.png"', "ENGINE_WORD_WEB_PICTURE"),
    (r'INCLUDEPICTURE "\\\\server.invalid\\p.png" \d', "ENGINE_WORD_REMOTE_INCLUDE"),
    ('INCLUDEPICTURE "search-ms:query=inert"', "ENGINE_WORD_REMOTE_INCLUDE"),
    (f"INCLUDEPICTURE {NESTED}", "ENGINE_WORD_REMOTE_INCLUDE"),
    (r'INCLUDEPICTURE "C:\\pics\\p.png"', "ENGINE_WORD_LOCAL_INCLUDE"),
    (f"{NESTED} x", "ENGINE_WORD_FIELDS_UNDETERMINED"),
])
def test_each_field_is_classified_by_its_type_and_target(instruction, rule):
    assert classify(Field("word/document.xml", instruction))[0] == rule


@pytest.mark.parametrize("instruction", [
    "PAGE", r'TOC \o "1-3" \h', f'HYPERLINK "{WEB}/"', "MERGEFIELD DDEAUTO", r"PAGEREF _Toc1 \h", "INCLUDETEXT",
    r"INCLUDEPICTURE \d", "DDEAUTOX cmd x", "",
])
def test_other_fields_and_fields_without_a_target_are_not_reported(instruction):
    assert classify(Field("word/document.xml", instruction)) is None


# ----------------------------------------------------------------------------- whole packages

def test_findings_name_the_part_and_show_the_instruction():
    found = wf.findings(wf.scan(docx(simple(CMD) + complex_field(f'INCLUDETEXT "{WEB}/a.docx"'))))
    by = {f.rule_id: f for f in found}
    assert {r: f.severity.value for r, f in by.items()} == {"ENGINE_WORD_DDEAUTO_PROGRAM": "HIGH",
                                                            "ENGINE_WORD_REMOTE_INCLUDE": "MEDIUM"}
    assert by["ENGINE_WORD_DDEAUTO_PROGRAM"].evidence == [f"word/document.xml: {CMD}"]
    assert all(f.scanner == "word-fields" and f.category == "office-field-code" for f in found)


def test_fields_in_every_loaded_part_are_read_and_unloaded_parts_are_ignored():
    header = f'{fx.XML}<w:hdr xmlns:w="{W}">{simple("DDE cmd x")}</w:hdr>'
    loaded = docx(main_rels=(("rId9", f"{fx.REL}/header", "header1.xml"),),
                  overrides={"word/header1.xml": f"{fx.OFFICE}.wordprocessingml.header+xml"},
                  parts={"word/header1.xml": header})
    assert rules(loaded) == [("ENGINE_WORD_DDE_PROGRAM", "MEDIUM")]
    orphan = docx(overrides={"word/header1.xml": f"{fx.OFFICE}.wordprocessingml.header+xml"},
                  parts={"word/header1.xml": header})
    assert rules(orphan) == []  # no relationship leads to it: Word never reads it


def test_unreadable_parts_and_imported_chunks_are_reported_as_undetermined():
    malformed = fx.office_package("docx", main_xml=document(simple("PAGE"))[:-20])
    assert rules(malformed) == [("ENGINE_WORD_FIELDS_UNDETERMINED", "INFO")]
    chunk = docx(main_rels=(("rId9", f"{fx.REL}/aFChunk", "chunk.rtf"),), defaults={"rtf": "application/rtf"},
                 parts={"word/chunk.rtf": "{\\rtf1 inert}"})
    assert rules(chunk) == [("ENGINE_WORD_FIELDS_UNDETERMINED", "INFO")]


def test_only_word_packages_are_handled():
    assert wf.scan(fx.office_package("xlsx")) is None and wf.scan(fx.office_package("pptx")) is None
    assert wf.scan(fx.plain_pdf()) is None and wf.scan(b"") is None
    assert wf.findings(wf.scan(docx(simple("PAGE")))) == []


# ----------------------------------------------------------------------------- inside the engines

NESTED_DDE = (f'<w:p>{BEGIN}{run("<w:instrText>DDEAUTO </w:instrText>")}{BEGIN}'
              f'{run("<w:instrText>QUOTE 99 109 100</w:instrText>")}{END}{run("<w:instrText> x</w:instrText>")}{END}</w:p>')
HEADER = f'{fx.XML}<w:hdr xmlns:w="{W}">{simple("DDEAUTO cmd x")}</w:hdr>'


@pytest.mark.parametrize("data, reference_verdict, unified_verdict, rule", [
    (docx(NESTED_DDE), "SAFE", "MALICIOUS", "ENGINE_WORD_DDEAUTO_PROGRAM"),  # QUOTE obfuscation
    (docx(complex_field(("DDEAUTO cmd x", "del"))), "SAFE", "SAFE", "ENGINE_WORD_DELETED_INSTRUCTION"),  # no claim
    (docx(main_rels=(("rId9", f"{fx.REL}/header", "parts/h.xml"),),
          overrides={"word/parts/h.xml": f"{fx.OFFICE}.wordprocessingml.header+xml"}, parts={"word/parts/h.xml": HEADER}),
     "SAFE", "MALICIOUS", "ENGINE_WORD_DDEAUTO_PROGRAM"),  # a loaded part outside the reference's name list
    (docx(simple(f'INCLUDETEXT "{WEB}/a.docx"')), "SAFE", "SUSPICIOUS", "ENGINE_WORD_REMOTE_INCLUDE"),
    (docx(simple(r'INCLUDEPICTURE "\\\\server.invalid\\p.png" \d')), "SAFE", "SUSPICIOUS", "ENGINE_WORD_REMOTE_INCLUDE"),
    (docx(simple(rf'INCLUDEPICTURE "{WEB}/p.png" \* MERGEFORMATINET')), "SAFE", "SAFE", "ENGINE_WORD_WEB_PICTURE"),
])
def test_what_c7_adds_to_the_reference_engine(data, reference_verdict, unified_verdict, rule):
    reference = worker.analyse(SCANNERS, data)
    unified = engine.correlate(worker.analyse(engine.SCANNERS, data))
    assert (verdicts(reference)["aggregate"], verdicts(unified)["aggregate"]) == (reference_verdict, unified_verdict)
    assert rule in {f.rule_id for f in unified.findings if f.scanner == "word-fields"}


@pytest.mark.parametrize("data, reference_rule", [
    (docx(simple(CMD)), "OFFICE_DDEAUTO_FIELD"),
    (docx(simple(r'DDEAUTO Excel "C:\\inert\\b.xlsx" R1C1')), "OFFICE_DDEAUTO_FIELD"),  # C7: LOW; reference: HIGH
    (docx(simple("DDE Excel Sheet1 R1C1")), "OFFICE_DDE_FIELD"),
    (docx(overrides={"word/header1.xml": f"{fx.OFFICE}.wordprocessingml.header+xml"},
          parts={"word/header1.xml": HEADER}), "OFFICE_DDEAUTO_FIELD"),  # never loaded: C7 silent
])
def test_reference_field_findings_always_stand_in_the_unified_engine(data, reference_rule):
    reference = worker.analyse(SCANNERS, data)
    unified = engine.correlate(worker.analyse(engine.SCANNERS, data))
    assert reference_rule in {f.rule_id for f in unified.findings if f.scanner == "office"}
    assert verdicts(unified)["aggregate"] == verdicts(reference)["aggregate"]


def test_every_existing_case_is_unchanged_by_c7():
    for case in cases():
        unified = engine.correlate(worker.analyse(engine.SCANNERS, case["data"]))
        assert [f for f in unified.findings if f.scanner == "word-fields"] == [], case["id"]
        status = {s.name: s.status for s in unified.scanners}["word-fields"]
        assert status == ("completed" if case["id"].startswith(("6", "7")) else "not_applicable"), case["id"]


def test_the_isolated_worker_runs_c7():
    report = asyncio.run(worker.run(docx(simple(CMD)), worker.command() + ["--engine=unified"]))
    assert {s.name: s.status for s in report.scanners}["word-fields"] == "completed"
    assert verdicts(report)["aggregate"] == "MALICIOUS"
