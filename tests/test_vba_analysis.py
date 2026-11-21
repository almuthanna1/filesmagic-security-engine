"""The engine's own VBA analysis (app.engine.vba_analysis): tokens, entry points, capabilities in
context, static deobfuscation, and its bounds.

Every source here is an inert string: placeholder arguments ("placeholder", example.test), no
working command, URL or payload. Nothing is executed; the analysis never runs code either.
"""

import re
import time

import pytest
from oletools.olevba import AUTOEXEC_KEYWORDS, AUTOEXEC_KEYWORDS_REGEX

from app.engine import vba_analysis as va


def analyse(body: str, procedures=("autoopen",)):
    src = f"Sub AutoOpen()\n{body}\nEnd Sub\n"
    lines = va.logical_lines(src)
    return va.analyse_code(lines, va.context([("Module1", lines)], set(procedures)))


def caps(body: str, **kw):
    return {(c.kind, c.status) for c in analyse(body, **kw).capabilities}


def folded(expr: str, env=None):
    v = va.fold(va.tokenize(expr), env)
    return None if v is None else (v.v, v.definite)


# ----------------------------------------------------------------------------- A. lines and tokens


def test_line_continuations_are_joined_with_the_first_line_number():
    assert va.logical_lines('a = "x" _\n  & "y"\nb = 1') == [(1, 'a = "x"   & "y"'), (3, "b = 1")]


def test_tokens_drop_comments_but_keep_quotes_inside_strings():
    toks = va.tokenize("x = \"it's \"\"quoted\"\"\" ' Shell \"not code\"")
    assert [t.kind for t in toks] == ["id", "op", "str"] and toks[2].value == 'it\'s "quoted"'
    assert va.tokenize('Rem Shell "x"') == [] and va.tokenize('x = 1: Rem Shell "x"')[-1].is_op(":")


def test_numbers_identifiers_and_type_suffixes():
    toks = va.tokenize("a$ = &HFF + &H7FFF& + &O17 + [Odd Name]")
    assert toks[0].value == "a" and [t.value for t in toks if t.kind == "num"] == [255, 0x7FFF, 15]
    assert toks[-1].value == "odd name" and va.tokenize("&HFFFF")[0].value == -1


def test_one_line_if_is_split_into_statements():
    assert len(va.statements(va.tokenize('If a Then Shell "p" Else MsgBox 1: b = 2'))) == 4


# ----------------------------------------------------------------------------- B. entry points


@pytest.mark.parametrize("name, kind", [
    ("AutoOpen", va.AUTOMATIC), ("Document_Open", va.AUTOMATIC), ("Workbook_Open", va.AUTOMATIC),
    ("Auto_Open2", va.AUTOMATIC), ("appWord_DocumentOpen", va.AUTOMATIC),
    ("InkPicture1_Painted", va.ACTIVEX), ("Frame1_Layout", va.ACTIVEX),
    ("CommandButton1_Click", va.USER), ("TextBox1_Change", va.USER),
    ("Helper", None), ("Click", None), ("OpenFile", None),
])
def test_entry_trigger_kinds(name, kind):
    assert va.entry_trigger(name) == kind


# Names olevba lists that are deliberately not entries, each with the reason.
NOT_ENTRIES = {
    "auto_ope": "olevba's substring keyword; Excel runs only names starting with Auto_Open (covered by a pattern)",
    "workbook_close": "not an Excel event (the event is Workbook_BeforeClose); Excel never calls it",
}


def test_every_olevba_entry_keyword_is_covered_or_excluded_with_a_reason():
    # Coverage parity with the baseline's third-party table: no trigger is silently lost.
    for keywords in AUTOEXEC_KEYWORDS.values():
        for k in keywords:
            assert va.entry_trigger(k) or k.lower() in NOT_ENTRIES, k
    for patterns in AUTOEXEC_KEYWORDS_REGEX.values():
        for p in patterns:
            example = re.sub(r"\\w\+", "Control1", p)
            assert va.entry_trigger(example), p


# ----------------------------------------------------------------------------- C. capabilities


@pytest.mark.parametrize("body, expected", [
    ('    Shell "placeholder"', ("execute", va.DEMONSTRATED)),
    ('    VBA.Shell "placeholder", vbHide', ("execute", va.DEMONSTRATED)),
    ('    Set o = CreateObject("WScript.Shell")\n    o.Run "placeholder"', ("execute", va.DEMONSTRATED)),
    ('    CreateObject("Shell.Application").ShellExecute "placeholder"', ("execute", va.DEMONSTRATED)),
    ('    GetObject("winmgmts:").Get("Win32_Process").Create "placeholder"', ("execute", va.DEMONSTRATED)),
    ('    With CreateObject("WScript.Shell")\n        .Exec "placeholder"\n    End With', ("execute", va.DEMONSTRATED)),
    ('    CallByName CreateObject("WScript.Shell"), "Run", VbMethod, "placeholder"', ("execute", va.DEMONSTRATED)),
    ('    Set h = CreateObject("MSXML2.XMLHTTP")\n    h.Open "GET", "https://example.test/", False',
     ("download", va.DEMONSTRATED)),
    ('    CreateObject("WScript.Shell").RegWrite "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x", "p"',
     ("persistence", va.DEMONSTRATED)),
    ('    x = obj.Run(1)', ("execute", va.POSSIBLE)),
    ('    Set o = CreateObject("WScript.Shell")', ("execute", va.POSSIBLE)),
])
def test_capabilities_in_context(body, expected):
    assert expected in caps(body)


def test_folded_progid_is_resolved():
    assert ("execute", va.DEMONSTRATED) in caps(
        '    Set o = CreateObject("WScr" & "ipt." & StrReverse("llehS"))\n    o.Run "placeholder"')


def test_project_wide_set_resolves_a_module_variable():
    src = ('Dim sh As Object\nSub Init()\n    Set sh = CreateObject("WScript.Shell")\nEnd Sub\n'
           'Sub AutoOpen()\n    sh.Run "placeholder"\nEnd Sub\n')
    lines = va.logical_lines(src)
    analysis = va.analyse_code(lines[4:], va.context([("M", lines)], {"init", "autoopen"}))
    assert ("execute", va.DEMONSTRATED) in {(c.kind, c.status) for c in analysis.capabilities}


@pytest.mark.parametrize("body", [
    '    Application.Run "Macro1"',  # starts a macro, not a program
    "    style = vbHide",  # a constant, not a call
    '    MsgBox "Shell"',  # a word in a string
    "    x = obj.Create(1)",  # a common method name
    '    ActiveDocument.Shapes(1).Select',
    '    Range("A1").Value = "powershell"',  # an interpreter name in data: weak at most
])
def test_no_strong_capability_without_an_operation(body):
    assert not [c for c in analyse(body).capabilities if c.strong and c.status == va.DEMONSTRATED]


def test_a_user_procedure_named_shell_shadows_the_builtin():
    assert caps('    Shell "placeholder"', procedures=("autoopen", "shell")) <= {("execute", va.POSSIBLE)}
    assert ("execute", va.POSSIBLE) in caps('    Shell "placeholder"', procedures=("autoopen", "shell"))


def test_declared_api_decides_not_the_library():
    def declared(alias):
        src = f'Private Declare PtrSafe Function F Lib "kernel32" Alias "{alias}" () As LongPtr\nSub AutoOpen()\n    F\nEnd Sub\n'
        lines = va.logical_lines(src)
        ctx = va.context([("M", lines)], {"autoopen"})
        # The capability belongs to the Declare line; vba_chains links callers to it as a procedure.
        return {c.kind for c in va.analyse_code(lines, ctx).capabilities if c.strong}
    assert "inject" in declared("VirtualAlloc") and not declared("GetTickCount")


def test_xlm_macro_sheet_functions():
    entries, found = va.analyse_xlm("' SHEET: Macro1, Macrosheet\n' Auto_Open\n=EXEC(\"placeholder\")\n=HALT()")
    assert [c.kind for c in found if c.strong] == ["execute"]
    assert va.analyse_xlm('=ALERT("exec is a word")') == ([], [])


# ----------------------------------------------------------------------------- D. deobfuscation


@pytest.mark.parametrize("expr, value", [
    ('"a" & "b" + "c"', "abc"),
    ("Chr(72) & ChrW(&H69)", "Hi"),
    ('StrReverse("cba")', "abc"),
    ('Replace("pXwXr", "X", "o")', "powor"),
    ('Mid("abcdef", 2, 3) & Left("xy", 1) & Right("xy", 1)', "bcdxy"),
    ("Chr(100 Xor 1)", "e"),
    ("Chr(Asc(\"a\") + 1)", "b"),
    ("(2 + 3) * 4 \\ 3 Mod 4", 2),
    ('UCase(Trim("  ab "))', "AB"),
])
def test_fold_constant_expressions(expr, value):
    assert folded(expr) == (value, True)


def test_a_variable_makes_a_fold_uncertain():
    env = {"p": va.Value("power", definite=False)}
    assert folded('p & "shell"', env) == ("powershell", False)


@pytest.mark.parametrize("expr", ['"a" & x', "Chr(70000)", "1 / 0", "Foo(1)", 'Shell("a")', "2 ^ 99"])
def test_unsupported_or_unknown_expressions_stop_the_fold(expr):
    assert folded(expr) is None


def test_hiding_methods_and_revealed_tokens_are_reported():
    decoded = analyse('    s = StrReverse("exe.llehsrewop")').decoded
    assert decoded and decoded[0].definite and "powershell" in " ".join(decoded[0].revealed)
    assert analyse('    s = "power" & "point"').decoded == []  # concatenation that reveals nothing


def test_encoded_literals_are_uncertain_evidence():
    import base64
    b64 = base64.b64encode("Write-Output placeholder".encode("utf-16-le")).decode()
    assert va.decode_literal(b64) == ("base64-literal", "Write-Output placeholder")
    assert va.decode_literal("68656c6c6f2c20776f726c64") == ("hex-literal", "hello, world")
    assert va.decode_literal("deadbeefdeadbeef") is None  # not readable text
    decoded = analyse(f'    s = "{b64}"').decoded
    assert decoded and not decoded[0].definite


# ----------------------------------------------------------------------------- bounds


def test_bounds_keep_hostile_source_fast_and_small():
    start = time.monotonic()
    assert folded('Replace(String(4096, "a") & String(4096, "a"), "a", String(4096, "b"))') is None  # 32M chars
    assert folded("(" * 1000 + "1" + ")" * 1000) is None  # nesting beyond MAX_DEPTH
    assert len(va.logical_lines("x" * (va.MAX_LINE_CHARS * 2))[0][1]) == va.MAX_LINE_CHARS
    analyse("\n".join(f'    s{i} = Chr({i % 90 + 32}) & "x" & StrReverse("ab")' for i in range(5000)))
    assert time.monotonic() - start < 10


def test_extraction_errors_are_returned_and_results_cached(monkeypatch):
    calls = []

    class Broken:
        def __init__(self, label, data=None):
            calls.append(label)
            raise RuntimeError("not a VBA project")

    monkeypatch.setattr(va, "VBA_Parser", Broken)
    va.extract.cache_clear()
    first = va.extract(b"blob", "x")
    assert isinstance(first.error, RuntimeError) and va.extract(b"blob", "x") is first and calls == ["x"]
    va.extract.cache_clear()
