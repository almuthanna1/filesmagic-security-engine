"""VBA call graphs on inert source strings.

Every module below is a Python string that never becomes a document or a VBA project. The
"dangerous" lines only carry a keyword olevba recognises, with placeholder arguments
(Shell "placeholder"), so nothing here could run anything even if typed into an editor.
"""

import pytest

from app.engine import vba_chains
from app.engine.vba_chains import LINKED, NO_PATH, UNDETERMINED, VbaChainError, analyse
from tests.office_fixtures import make_ole, make_ooxml

TOOL = 'Sub RunTool()\n    Shell "placeholder"\nEnd Sub\n'


def outcome(*sources: str, problems=None):
    result = analyse([(f"Module{i}", s) for i, s in enumerate(sources, 1)], problems)
    return result.outcome, [(e.entry, e.outcome, e.path) for e in result.entries], result


def test_related_procedures_establish_a_path_through_transitive_calls():
    src = "Sub AutoOpen()\n    Prepare\nEnd Sub\nSub Prepare()\n    Call RunTool\nEnd Sub\n" + TOOL
    overall, entries, _ = outcome(src)
    assert overall == LINKED
    assert entries == [("Module1.AutoOpen", LINKED, ("Module1.AutoOpen", "Module1.Prepare", "Module1.RunTool"))]


def test_calls_across_modules_are_followed():
    overall, entries, _ = outcome("Sub Document_Open()\n    Module2.RunTool\nEnd Sub\n", TOOL)
    assert overall == LINKED and entries[0][2] == ("Module1.Document_Open", "Module2.RunTool")


def test_an_unrelated_dangerous_procedure_gives_no_path():
    # The reference Office scanner rates this HIGH: automatic entry and Shell in the same project.
    src = 'Sub AutoOpen()\n    MsgBox "Hello"\nEnd Sub\n' + TOOL
    overall, entries, result = outcome(src)
    assert (overall, entries) == (NO_PATH, [("Module1.AutoOpen", NO_PATH, ())]) and not result.problems


def test_names_in_comments_and_strings_are_not_calls():
    src = "Sub AutoOpen()\n    ' RunTool is called elsewhere\n    MsgBox \"RunTool\"\nEnd Sub\n" + TOOL
    assert outcome(src)[0] == NO_PATH


def test_call_cycles_terminate():
    src = "Sub AutoOpen()\n    PingA\nEnd Sub\nSub PingA()\n    PingB\nEnd Sub\nSub PingB()\n    PingA\nEnd Sub\n" + TOOL
    assert outcome(src)[0] == NO_PATH


@pytest.mark.parametrize("call", [
    'Application.Run "RunTool"',
    'Application.Run "Module1.RunTool"',
    "Application.Run \"'Book.xlsm'!Module1.RunTool\"",
    'Application.OnTime Now, "RunTool"',
    "x = EnumWindows(AddressOf RunTool, 0)",
])
def test_indirect_calls_naming_a_procedure_are_resolved(call):
    assert outcome(f"Sub Workbook_Open()\n    {call}\nEnd Sub\n" + TOOL)[0] == LINKED


@pytest.mark.parametrize("call, reason", [
    ('Application.OnKey "^q", procName', "calls OnKey with a name that is not a known procedure"),
    ('CallByName obj, "Unknown" & suffix, VbMethod', "calls CallByName"),
    ('x = Evaluate("A1")', "uses Evaluate"),
    ('ThisWorkbook.VBProject.VBComponents(1).CodeModule.AddFromString "x"', "uses VBProject"),
])
def test_dynamic_calls_on_the_reachable_part_make_the_path_undetermined(call, reason):
    overall, _, result = outcome(f'Sub AutoOpen()\n    {call}\nEnd Sub\n' + 'Sub Other()\n    MsgBox "x"\nEnd Sub\n')
    assert overall == UNDETERMINED and reason in result.entries[0].reasons[0]


def test_run_with_a_computed_name_is_itself_a_capability_for_olevba():
    # olevba lists "Run" under "May run an executable file or a system command", which the Office
    # scanner rates strong, so the procedure making the dynamic call is a capability node.
    overall, entries, _ = outcome("Sub AutoOpen()\n    Application.Run procName\nEnd Sub\n")
    assert overall == LINKED and entries[0][2] == ("Module1.AutoOpen",)


def test_a_dynamic_call_outside_the_reachable_part_does_not_matter():
    src = 'Sub AutoOpen()\n    MsgBox "x"\nEnd Sub\nSub Elsewhere()\n    Application.Run procName\nEnd Sub\n' + TOOL
    assert outcome(src)[0] == NO_PATH


def test_an_established_path_wins_over_a_dynamic_call():
    src = "Sub AutoOpen()\n    Application.Run procName\n    RunTool\nEnd Sub\n" + TOOL
    assert outcome(src)[0] == LINKED


def test_an_aliased_library_declaration_links_a_harmless_looking_call():
    # The call site "OpenIt 0" carries no keyword; only the declaration names the real function.
    src = ('Private Declare PtrSafe Function OpenIt Lib "shell32" Alias "ShellExecuteA" (ByVal h As LongPtr) As LongPtr\n'
           "Sub AutoOpen()\n    OpenIt 0\nEnd Sub\n")
    assert outcome(src)[1][0][2] == ("Module1.AutoOpen", "Module1.OpenIt")


@pytest.mark.parametrize("src, problem", [
    ('Sub AutoOpen()\n    MsgBox "x"\n' + TOOL, "has no End before RunTool"),
    ('Sub AutoOpen()\n    MsgBox "x"\n', "is never ended"),
    ('Const TOOL_CMD = "placeholder"\nPublic x As Object\nSub AutoOpen()\n    MsgBox "x"\nEnd Sub\n'
     'Sub Helper()\nEnd Sub\nEnd Sub\n', "End without a procedure"),
    ('Dim s As Object: Set s = CreateObject("WScript.Shell")\nSub AutoOpen()\n    MsgBox "x"\nEnd Sub\n',
     "dangerous keywords outside any procedure"),
    ("Sub Main()\n    ' started from AutoOpen in another file\nEnd Sub\n" + TOOL, "automatic-entry keyword 'AutoOpen'"),
])
def test_incomplete_call_graphs_are_undetermined(src, problem):
    overall, _, result = outcome(src)
    assert overall == UNDETERMINED and any(problem in p for p in result.problems)


def test_extraction_problems_make_any_no_path_undetermined():
    src = 'Sub AutoOpen()\n    MsgBox "x"\nEnd Sub\n'
    assert outcome(src)[0] == NO_PATH
    assert outcome(src, problems=["vbaProject.bin could not be extracted"])[0] == UNDETERMINED


def test_no_entry_means_nothing_runs_automatically():
    assert outcome(TOOL)[:2] == (NO_PATH, [])


# ----------------------------------------------------------------------------- documents


class SourceOnlyParser:
    """Stands in for olevba.VBA_Parser's container parsing only: it hands over inert source
    strings. No VBA project is built; keyword analysis stays real olevba."""

    modules: list[tuple[str, str]] = []
    fail = False

    def __init__(self, label, data=None):
        pass

    def detect_xlm_macros(self):
        return False

    def detect_vba_macros(self):
        return bool(self.modules)

    def extract_macros(self):
        if self.fail:
            raise RuntimeError("cannot decompress")
        for name, code in self.modules:
            yield "vbaProject.bin", "VBA/" + name, name, code

    def close(self):
        pass


@pytest.fixture
def parser(monkeypatch):
    monkeypatch.setattr(vba_chains, "VBA_Parser", SourceOnlyParser)
    monkeypatch.setattr(SourceOnlyParser, "fail", False)
    return SourceOnlyParser


DOCM = make_ooxml({"word/vbaProject.bin": make_ole({"VBA/dir": b"x"})})  # an OLE container, no VBA project


def test_documents_are_analysed_through_their_vba_containers(parser, monkeypatch):
    monkeypatch.setattr(parser, "modules", [("Module1", 'Sub AutoOpen()\n    MsgBox "x"\nEnd Sub\n' + TOOL)])
    assert vba_chains.scan(DOCM).outcome == NO_PATH


def test_a_project_that_cannot_be_extracted_is_undetermined(parser, monkeypatch):
    monkeypatch.setattr(parser, "modules", [("Module1", "x")])
    monkeypatch.setattr(parser, "fail", True)
    result = vba_chains.scan(DOCM)
    assert result.outcome == UNDETERMINED and "could not be extracted (RuntimeError)" in result.problems[0]


def test_a_vba_part_that_is_not_ole_is_undetermined(parser):
    result = vba_chains.scan(make_ooxml({"word/vbaProject.bin": b"not an OLE file"}))
    assert result.outcome == UNDETERMINED and "is not an OLE VBA project" in result.problems[0]


def test_non_office_files_and_projects_without_vba_are_not_applicable(parser):
    assert vba_chains.scan(b"%PDF-1.7 not office") is None
    assert vba_chains.scan(make_ooxml({})) is None


def test_a_broken_package_fails_closed_as_malformed_input():
    with pytest.raises(VbaChainError) as e:
        vba_chains.scan(b"PK\x03\x04 [Content_Types].xml truncated")
    assert type(e.value.__cause__).__name__ == "BadZipFile"


# ----------------------------------------------------------------------------- unified engine


class SourceOnlyOfficeParser(SourceOnlyParser):
    """Also stands in for the Office scanner's olevba calls; its keyword analysis is real olevba
    (VBA_Scanner) over the same inert source."""

    def detect_macros(self):
        return bool(self.modules)

    def analyze_macros(self):
        from oletools.olevba import VBA_Scanner
        return VBA_Scanner("\n".join(code for _, code in self.modules)).scan()


RELATED = "Sub AutoOpen()\n    Prepare\nEnd Sub\nSub Prepare()\n    RunTool\nEnd Sub\n" + TOOL
UNRELATED = 'Sub AutoOpen()\n    MsgBox "Hello"\nEnd Sub\n' + TOOL
UNDETERMINED_SRC = 'Sub AutoOpen()\n    Application.OnKey "^q", procName\nEnd Sub\n' + TOOL


@pytest.mark.parametrize("source, engine_rule, note", [
    (RELATED, "ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY", "confirmed by a macro call path"),
    (UNRELATED, "ENGINE_VBA_NO_CALL_PATH", "kept although the source shows no call path"),
    (UNDETERMINED_SRC, "ENGINE_VBA_CALL_PATH_UNDETERMINED", "kept: the macro call path could not be determined"),
])
def test_the_reference_macro_verdict_is_qualified_never_lowered(monkeypatch, source, engine_rule, note):
    from app import engine, worker
    from app.scanners import SCANNERS, office
    from evaluation.cases import verdicts

    monkeypatch.setattr(SourceOnlyOfficeParser, "modules", [("Module1", source)])
    monkeypatch.setattr(office, "VBA_Parser", SourceOnlyOfficeParser)
    monkeypatch.setattr(vba_chains, "VBA_Parser", SourceOnlyOfficeParser)
    reference = worker.analyse(SCANNERS, DOCM)
    unified = engine.correlate(worker.analyse(engine.SCANNERS, DOCM))
    rules = {f.rule_id for f in unified.findings}
    assert "OFFICE_MACRO_AUTOEXEC_EXECUTION" in {f.rule_id for f in reference.findings} & rules
    assert engine_rule in rules
    assert note in next(f.description for f in unified.findings if f.rule_id == "ENGINE_CORRELATION")
    assert verdicts(unified)["aggregate"] == verdicts(reference)["aggregate"] == "MALICIOUS"
