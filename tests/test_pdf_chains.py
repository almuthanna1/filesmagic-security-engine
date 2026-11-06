import pytest

from app.engine.pdf_chains import COMPUTED, ChainScanError, scan
from evaluation.cases import cases
from tests.pdf_fixtures import attachment, encrypted_pdf, js_action, make_pdf

CASE = {c["id"]: c["data"] for c in cases()}


def summary(data: bytes) -> list[tuple]:
    return [(c.trigger, c.automatic, [a.kind for a in c.actions]) for c in scan(data).chains]


def test_a_page_destination_does_not_make_that_pages_click_scripts_automatic():
    # The reference scanner reports PDF_AUTO_JAVASCRIPT here (case 2b).
    assert summary(CASE["2b-pdf-open-at-page-click-js"]) == [("object 5 0 /A", False, ["JavaScript"])]


def test_form_keystroke_script_is_user_triggered():
    assert summary(CASE["2-pdf-form-keystroke-js"]) == [("object 5 0 /AA /K", False, ["JavaScript"])]


@pytest.mark.parametrize("case", ["3-pdf-escaped-openaction-js", "4-pdf-objstm-escaped-js"])
def test_escaped_names_and_object_streams_are_read_through_pypdf(case):
    assert summary(CASE[case]) == [("catalog /OpenAction", True, ["JavaScript"])]


def test_an_attachment_the_automatic_script_never_names_is_not_linked():
    result = scan(CASE["5a-pdf-auto-js-unrelated-attachment"])
    assert result.attachments == {"f", "notes.txt"}
    assert [c.automatic for c in result.chains] == [True] and result.linked(result.chains[0]) == []


def test_an_automatic_script_exporting_the_attachment_is_linked():
    result = scan(CASE["5b-pdf-auto-js-exports-attachment"])
    assert [(name, how) for _, name, how in result.linked(result.chains[0])] == [("f", "export")]


def test_a_computed_data_object_name_links_to_every_attachment():
    extra, objs = attachment("notes.txt")
    data = make_pdf(catalog_extra="/OpenAction 7 0 R " + extra,
                    objects={**objs, 7: js_action("var n = 'f'; this.exportDataObject\\({cName: n}\\);")})
    result = scan(data)
    assert [(name, how) for _, name, how in result.linked(result.chains[0])] == [(COMPUTED, "export")]


def test_next_actions_join_the_chain_in_order_and_cycles_terminate():
    data = make_pdf(catalog_extra="/OpenAction 5 0 R", objects={
        5: "<< /S /URI /URI (https://example.com/) /Next [6 0 R 7 0 R] >>",
        6: "<< /S /GoTo /D [3 0 R /Fit] >>",
        7: "<< /S /JavaScript /JS (app.alert\\(1\\);) /Next 5 0 R >>",
    })
    assert summary(data) == [("catalog /OpenAction", True, ["URI", "GoTo", "JavaScript"])]


def test_launch_of_an_embedded_file_is_a_payload_and_an_external_target_is_not():
    extra, objs = attachment("tool.exe")
    data = make_pdf(catalog_extra="/OpenAction 7 0 R " + extra,
                    objects={**objs, 7: "<< /S /Launch /F 5 0 R >>", 8: "<< /S /Launch /F (calc.exe) >>"},
                    page_extra="/AA << /O 8 0 R >>")
    by_trigger = {c.trigger: c.actions[0] for c in scan(data).chains}
    assert by_trigger["catalog /OpenAction"].payload == (("tool.exe", "launch"),)
    assert by_trigger["object 3 0 /AA /O"].target == "calc.exe"


def test_document_level_scripts_and_page_open_actions_are_automatic():
    data = make_pdf(catalog_extra="/Names << /JavaScript << /Names [(init) 5 0 R] >> >>",
                    page_extra="/AA << /O 6 0 R /C 6 0 R >>", objects={5: js_action(), 6: js_action()})
    assert sorted(summary(data)) == [("document-level script 'init'", True, ["JavaScript"]),
                                     ("object 3 0 /AA /C", False, ["JavaScript"]),
                                     ("object 3 0 /AA /O", True, ["JavaScript"])]


def test_goto_embedded_names_its_target_file():
    data = make_pdf(catalog_extra="/OpenAction << /S /GoToE /T << /R /C /N (inner.pdf) >> >>")
    assert scan(data).chains[0].actions[0].payload == (("inner.pdf", "open"),)


def test_not_a_pdf_is_not_applicable():
    assert scan(b"PK\x03\x04 not a pdf") is None


@pytest.mark.parametrize("data", [encrypted_pdf("secret"), b"%PDF-1.7\nnot a body\n%%EOF\n"])
def test_unreadable_pdfs_fail_closed(data):
    with pytest.raises(ChainScanError):
        scan(data)
