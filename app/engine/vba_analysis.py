"""FilesMagic VBA behaviour analysis: what macro source can do, decided by this repository's code.

oletools is used only to extract source (VBA_Parser.extract_macros: MS-OVBA decompression and
OLE stream walking). Everything below is our own analysis of that text; nothing is executed.

A. Lines and tokens. Physical lines ending in " _" are joined (VBA line continuation, also inside
   comments). A tokenizer turns each logical line into identifiers, string literals ("" is one
   quote), numbers (decimal, &H hex, &O octal), and operators, dropping comments (' anywhere
   outside a string, Rem where a statement starts). Statements are split at ":" and at the
   Then/Else of a one-line If.
B. Entry points (ENTRY_POINTS). Procedures Office runs without the macro being started by name:
   document lifecycle names (Word "Auto macros", Document_*/Workbook_* events, Excel Auto_Open*),
   ActiveX events that fire when a control loads or renders, and user events (click, change).
   Each match records its trigger kind; the table is ours, cross-checked against olevba's
   keyword list in tests (tests/test_vba_analysis.py) so no baseline trigger is silently lost.
C. Capabilities. Operations recognised in context, each DEMONSTRATED or only POSSIBLE:
     execute      Shell / VBA.Shell; WScript.Shell .Run/.Exec; Shell.Application .ShellExecute;
                  WMI Win32_Process .Create; ExecuteExcel4Macro("EXEC(...)"); MacScript; declared
                  ShellExecute/WinExec/CreateProcess; InvokeVerb; ExecuteShellCommand
     download     XMLHTTP / WinHttp .Open/.Send; declared URLDownloadToFile / WinINet
     inject       declared VirtualAlloc, RtlMoveMemory, WriteProcessMemory, CreateThread, shellcode
                  callback launchers (EnumSystemLanguageGroupsW, EnumDateFormats*, CallWindowProc)
     persistence  RegWrite to a Run key; a file written into the Startup folder; Task Scheduler
                  RegisterTaskDefinition; schtasks /create in an executed command
   plus weaker kinds (file writes, registry, environment, keystrokes, self-modification, native
   API declarations, interpreter names in strings) that are reported but never escalate.
   The receiver of a method decides: an object is tracked from CreateObject/GetObject/New
   (ProgID or CLSID, after constant folding), through Set assignments, With blocks and chained
   calls (GetObject("winmgmts:").Get("Win32_Process").Create). A module-level object variable
   that every Set in the project assigns the same kind of object resolves to that kind
   (flow-insensitive). Run/Exec/RegWrite on an object of unknown type is POSSIBLE; Run on the
   Office Application object starts a macro and is no execution at all. A name shadowed by a
   user procedure or variable (a procedure called Shell) is POSSIBLE, never DEMONSTRATED.
D. Static deobfuscation (fold). A recursive-descent evaluator for constant expressions only:
   string and integer literals, & and + concatenation, + - * \\ Mod Xor And Or ^ on integers,
   Chr/ChrW/ChrB, Asc, StrReverse, LCase/UCase, Trim, Left/Right/Mid, Replace (3 arguments),
   Len, Space, String, CStr/CLng/CInt, Hex, the vb* string constants, Const declarations and
   string variables assigned earlier in the same procedure. Anything else stops the fold. A
   result is DEFINITE if it uses only literals and constants, uncertain if it depends on a
   variable (straight-line order is assumed, branches are not followed). Encoded literals (hex,
   base64, UTF-16LE base64 as in PowerShell -EncodedCommand) are decoded only as uncertain
   evidence: nothing shows the macro decodes them. A folded string reveals something when it
   contains a sensitive token (interpreter, ProgID, API, URL, Run key) that none of the literals
   it was built from contains on its own: that is the obfuscation indicator.

Bounds: logical lines of at most MAX_LINE_CHARS, folded strings of at most MAX_FOLDED characters,
expression nesting of at most MAX_DEPTH, MAX_SOURCE_BYTES of source per document (in the
extraction). Unsupported syntax makes a fold stop, never guess.

Limitations, stated in findings where they apply: no data flow through branches, loops,
procedure arguments, cell values or document variables; no P-code analysis (VBA stomping: the
compiled code Office may run instead of the source is not examined); no Excel 4.0 (XLM) formula
evaluation (macro-sheet function names only, from the extractor's BIFF listing).
"""

import base64
import binascii
import functools
import re
from dataclasses import dataclass, field

from oletools.olevba import VBA_Parser

DEMONSTRATED, POSSIBLE = "demonstrated", "possible"
STRONG = ("execute", "download", "inject", "persistence")
AUTOMATIC, ACTIVEX, USER = "document open/close", "ActiveX control event", "user action"
MAX_LINE_CHARS = 64 * 1024
MAX_FOLDED = 64 * 1024
MAX_DEPTH = 48
MAX_SOURCE_BYTES = 8 * 1024 * 1024
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def clean(text: str, limit: int = 120) -> str:
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", str(text)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ----------------------------------------------------------------------------- A. lines and tokens


def logical_lines(source: str) -> list[tuple[int, str]]:
    """(first physical line number, logical line), continuations joined."""
    out, buf, start = [], [], None
    for n, raw in enumerate(re.split(r"\r\n|\r|\n", source), 1):
        start = n if start is None else start
        stripped = raw.rstrip()
        if stripped == "_" or stripped.endswith((" _", "\t_")):
            buf.append(stripped[:-1])
            continue
        buf.append(raw)
        out.append((start, "".join(buf)[:MAX_LINE_CHARS]))
        buf, start = [], None
    if buf:
        out.append((start, "".join(buf)[:MAX_LINE_CHARS]))
    return out


@dataclass(frozen=True)
class Tok:
    kind: str  # id, str, num, op
    text: str
    value: object = None  # id: lower-case name without type suffix or brackets; str: content; num: int

    def is_op(self, *ops: str) -> bool:
        return self.kind == "op" and self.text in ops

    def is_id(self, *names: str) -> bool:
        return self.kind == "id" and (not names or self.value in names)


_TOKEN = re.compile(r"""
    (?P<ws>[ \t\f\v\x00\xa0]+)
  | (?P<str>"(?:[^"]|"")*"?)
  | (?P<comment>')
  | (?P<num>&[Hh][0-9A-Fa-f]+&?(?![\w$])|&[Oo][0-7]+&?(?![\w$])|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[%&!#@]?)
  | (?P<id>\[[^\]\r\n]*\]|[A-Za-z_À-￿][\wÀ-￿]*(?:[$%!#@]|&(?![\w"(]))?)
  | (?P<op>:=|<=|>=|<>|[-+*/\\^&=<>(),.:;!\#{}?])
  | (?P<other>.)
""", re.X)


def _number(text: str) -> int | None:
    t = text.rstrip("%&!#@")
    try:
        if t[:2].lower() == "&h":
            v = int(t[2:], 16)
            return v - 0x10000 if len(t) <= 6 and v > 0x7FFF and not text.endswith("&") else v  # &HFFFF is -1
        if t[:2].lower() == "&o":
            return int(t[2:], 8)
        return int(t) if t.isdigit() else None  # floats are not folded
    except ValueError:
        return None


def tokenize(line: str) -> list[Tok]:
    toks: list[Tok] = []
    for m in _TOKEN.finditer(line):
        kind, text = m.lastgroup, m.group()
        if kind == "ws":
            continue
        if kind == "comment":
            break
        if kind == "id" and text.lower() == "rem" and (not toks or toks[-1].is_op(":")):
            break
        if kind == "str":
            body = text[1:-1] if len(text) > 1 and text.endswith('"') else text[1:]
            toks.append(Tok("str", text, body.replace('""', '"')))
        elif kind == "num":
            toks.append(Tok("num", text, _number(text)))
        elif kind == "id":
            toks.append(Tok("id", text, text.strip("[]").rstrip("$%!#@&").lower()))
        else:
            toks.append(Tok("op", text))
    return toks


def statements(toks: list[Tok]) -> list[list[Tok]]:
    out, cur = [], []
    for t in toks:
        if t.is_op(":") or t.is_id("then", "else"):
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    out.append(cur)
    return [s for s in out if s]


# ----------------------------------------------------------------------------- B. entry points

# Source: Microsoft Learn, "Auto macros" (Word), Document/Workbook/Worksheet object events, Excel
# "Run a macro automatically when opening a workbook" (Auto_Open; Excel runs any macro whose name
# starts with Auto_Open), Publisher Document events. Word Application events are handled in a
# class as <variable>_<Event>, so they are matched as suffixes too.
_AUTOMATIC_NAMES = {
    "autoexec", "autoopen", "autonew", "autoclose", "autoexit",
    "document_open", "document_new", "document_close", "document_beforeclose",
    "documentopen", "newdocument", "documentbeforeclose", "documentchange",
    "workbook_open", "workbook_activate", "workbook_beforeclose", "worksheet_calculate",
}
_AUTOMATIC_PATTERNS = [r"auto_open\w*", r"auto_close\w*", r"\w+_(documentopen|newdocument|documentbeforeclose|documentchange)"]
# Events that ActiveX controls raise when they load, render or receive focus, without a click
# (InkPicture Painted/Painting, WebBrowser navigation events, Frame Layout, focus events). The list
# matches the research olevba's AUTOEXEC_KEYWORDS_REGEX cites; we keep it as our own table.
_ACTIVEX_SUFFIXES = ("painted", "painting", "gotfocus", "lostfocus", "layout", "resize", "beforenavigate2",
                     "beforescriptexecute", "documentcomplete", "downloadbegin", "downloadcomplete",
                     "filedownload", "navigatecomplete2", "navigateerror", "progresschange", "propertychange",
                     "setsecurelockicon", "statustextchange", "titlechange", "onconnecting")
_USER_SUFFIXES = ("click", "dblclick", "change", "mousemove", "mousehover", "mouseenter", "mouseleave",
                  "followhyperlink", "contentcontrolonenter", "keypress", "keydown", "keyup",
                  "beforedoubleclick", "beforerightclick", "selectionchange")
ENTRY_NAMES = _AUTOMATIC_NAMES | {"auto_open", "auto_close"}  # names, for "mentioned but not defined"


def entry_trigger(name: str) -> str | None:
    """The trigger kind under which Office runs a procedure of this name, or None."""
    n = name.lower()
    if n in _AUTOMATIC_NAMES or any(re.fullmatch(p, n) for p in _AUTOMATIC_PATTERNS):
        return AUTOMATIC
    if "_" in n:
        suffix = n.rsplit("_", 1)[1]
        if suffix in _ACTIVEX_SUFFIXES:
            return ACTIVEX
        if suffix in _USER_SUFFIXES:
            return USER
    return None


# ----------------------------------------------------------------------------- C. tables

PROGIDS = {  # ProgID, type name or CLSID -> object kind
    "wscript.shell": "wscript.shell", "wshshell": "wscript.shell", "iwshruntimelibrary.wshshell": "wscript.shell",
    "{72c24dd5-d70a-438b-8a42-98424b88afb8}": "wscript.shell",
    "shell.application": "shell.application", "shell32.shell": "shell.application",
    "{13709620-c279-11ce-a49e-444553540000}": "shell.application",
    "{9ba05972-f6a8-11cf-a442-00a0c90a8f39}": "shell.application",  # ShellWindows
    "msxml2.xmlhttp": "http", "msxml2.serverxmlhttp": "http", "microsoft.xmlhttp": "http",
    "msxml2.xmlhttp60": "http", "msxml2.serverxmlhttp60": "http", "winhttp.winhttprequest": "http",
    "adodb.stream": "adodb.stream", "scripting.filesystemobject": "fso",
    "schedule.service": "task-scheduler", "mmc20.application": "mmc",
    "{49b2791a-b1ae-4c90-9b8e-e860ba07f889}": "mmc", "internetexplorer.application": "browser",
    "excel.application": "office-app", "word.application": "office-app", "powerpoint.application": "office-app",
    "outlook.application": "office-app",
}
EXEC_OBJECTS = {"wscript.shell": "Run or Exec", "shell.application": "ShellExecute"}
# Identifiers that name Office's own objects: Run on them starts a macro, not a program.
OFFICE_OBJECTS = {"application", "thisworkbook", "activeworkbook", "thisdocument", "activedocument",
                  "activesheet", "activepresentation", "workbooks", "documents", "sheets", "worksheets",
                  "excel", "word", "powerpoint"}
UNKNOWN = "unknown object"

# (object kind, method) -> (capability kind, description)
METHODS = {
    ("wscript.shell", "run"): ("execute", "WScript.Shell.Run starts a program or command"),
    ("wscript.shell", "exec"): ("execute", "WScript.Shell.Exec starts a program or command"),
    ("wscript.shell", "regwrite"): ("registry", "WScript.Shell.RegWrite writes the registry"),
    ("wscript.shell", "regread"): ("registry", "WScript.Shell.RegRead reads the registry"),
    ("wscript.shell", "expandenvironmentstrings"): ("environment", "reads environment variables"),
    ("shell.application", "shellexecute"): ("execute", "Shell.Application.ShellExecute starts a program"),
    ("wmi-process", "create"): ("execute", "WMI Win32_Process.Create starts a process"),
    ("http", "open"): ("download", "an HTTP request object opens a URL"),
    ("http", "send"): ("download", "an HTTP request object sends a request"),
    ("adodb.stream", "savetofile"): ("write-file", "ADODB.Stream.SaveToFile writes a file"),
    ("fso", "createtextfile"): ("write-file", "FileSystemObject.CreateTextFile writes a file"),
    ("fso", "copyfile"): ("file-operation", "FileSystemObject.CopyFile copies a file"),
    ("fso", "movefile"): ("file-operation", "FileSystemObject.MoveFile moves a file"),
    ("fso", "deletefile"): ("file-operation", "FileSystemObject.DeleteFile deletes a file"),
    ("browser", "navigate"): ("network", "InternetExplorer.Navigate opens a URL"),
}
# Method names specific to one dangerous operation, whatever the receiver.
SPECIFIC_METHODS = {
    "shellexecute": ("execute", "ShellExecute starts a program"),
    "invokeverb": ("execute", "InvokeVerb runs a shell verb on a file"),
    "invokeverbex": ("execute", "InvokeVerbEx runs a shell verb on a file"),
    "executeshellcommand": ("execute", "MMC20 ExecuteShellCommand starts a program"),
    "registertaskdefinition": ("persistence", "Task Scheduler RegisterTaskDefinition creates a scheduled task"),
}
# Ambiguous on an object of unknown type: POSSIBLE only (Run also starts macros, Exec is common).
AMBIGUOUS_METHODS = {
    "run": ("execute", "Run on an object of unknown type (WScript.Shell.Run would execute a command)"),
    "exec": ("execute", "Exec on an object of unknown type (WScript.Shell.Exec would execute a command)"),
    "regwrite": ("registry", "RegWrite on an object of unknown type"),
}
APIS = {  # declared Windows API (Alias or name, lower case) -> capability kind
    **dict.fromkeys(["shellexecutea", "shellexecutew", "shellexecute", "shellexecuteexa", "shellexecuteexw",
                     "winexec", "createprocessa", "createprocessw", "createprocessasusera", "createprocessasuserw",
                     "createprocesswithlogonw"], "execute"),
    **dict.fromkeys(["urldownloadtofilea", "urldownloadtofilew", "urldownloadtofile", "urldownloadtocachefilea",
                     "urldownloadtocachefilew", "internetopenurla", "internetopenurlw", "internetreadfile",
                     "httpsendrequesta", "httpsendrequestw", "winhttpsendrequest"], "download"),
    **dict.fromkeys(["virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex", "rtlmovememory",
                     "writeprocessmemory", "createthread", "createremotethread", "createuserthread", "queueuserapc",
                     "ntqueueapcthread", "setthreadcontext", "ntwritevirtualmemory", "rtlcreateuserthread",
                     "enumsystemlanguagegroupsw", "enumsystemlanguagegroupsa", "enumdateformatsw", "enumdateformatsa",
                     "enumdateformatsexw", "enumdateformatsexa", "enumdateformatsexex", "enumuilanguagesw",
                     "enumsystemcodepagesw", "callwindowproca", "callwindowprocw"], "inject"),
    **dict.fromkeys(["regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw", "regopenkeyexa",
                     "regopenkeyexw", "regqueryvalueexa", "regqueryvalueexw"], "registry"),
}
FUNCTIONS = {  # VBA built-in statement or function -> (capability kind, description)
    "kill": ("file-operation", "Kill deletes files"), "filecopy": ("file-operation", "FileCopy copies a file"),
    "mkdir": ("file-operation", "MkDir creates a folder"), "environ": ("environment", "Environ reads environment variables"),
    "sendkeys": ("keystrokes", "SendKeys simulates keystrokes"), "appactivate": ("keystrokes", "AppActivate switches applications"),
    "vbproject": ("self-modify", "accesses the VBA project (code can modify itself)"),
    "vbcomponents": ("self-modify", "accesses VBA components"), "codemodule": ("self-modify", "accesses a code module"),
    "addfromstring": ("self-modify", "adds code from a string"), "insertlines": ("self-modify", "inserts code lines"),
}
INTERPRETERS = ("powershell", "pwsh", "cmd.exe", "cmd /c", "cmd /k", "mshta", "wscript", "cscript", "rundll32",
                "regsvr32", "certutil", "bitsadmin", "msiexec", "schtasks", "wmic")
CRADLES = ("downloadstring", "downloadfile", "net.webclient", "invoke-expression", "iex(", "iex ", "start-process",
           "invoke-webrequest", "-encodedcommand", "frombase64string", "bitstransfer")
RUN_KEY = re.compile(r"\\software\\(wow6432node\\)?microsoft\\windows\\currentversion\\run(once)?(\\|$)", re.I)
STARTUP = re.compile(r"\\(start menu\\programs\\startup|startup)(\\|$)", re.I)
SENSITIVE = (INTERPRETERS + CRADLES + tuple(k for k in PROGIDS if not k.startswith("{"))
             + ("winmgmts", "win32_process", "http://", "https://", "ftp://", "\\currentversion\\run")
             + tuple(APIS) + ("exec(", "call(", "register("))
CREATORS = {"createobject", "getobject"}
# Fold operations whose only purpose in a constant expression is to hide the text they produce.
HIDING = {"chr", "strreverse", "replace", "xor", "asc"}
KEYWORDS = {"if", "elseif", "while", "do", "loop", "for", "select", "case", "call", "dim", "redim", "let", "print",
            "open", "close", "with", "end", "exit", "goto", "on", "return", "debug", "const", "public", "private",
            "global", "static", "declare", "sub", "function", "property", "option", "attribute", "type", "enum",
            "next", "wend", "until", "friend", "set", "resume", "erase", "get", "put", "input", "line", "write"}


def sensitive_in(text: str) -> list[str]:
    t = text.lower()
    return sorted({s.strip("( ") for s in SENSITIVE if s in t})


@dataclass(frozen=True)
class Capability:
    kind: str
    status: str
    what: str
    line: int
    detail: str = ""

    @property
    def strong(self) -> bool:
        return self.kind in STRONG

    def text(self) -> str:
        return f"{self.kind}: {self.what} (line {self.line}{', ' + self.detail if self.detail else ''})"


@dataclass(frozen=True)
class Decoded:
    line: int
    value: str
    methods: tuple[str, ...]
    definite: bool
    revealed: tuple[str, ...]  # sensitive tokens no single input literal contains

    def text(self) -> str:
        how = "+".join(self.methods)
        sure = "definite" if self.definite else "uncertain"
        hidden = f"; reveals {', '.join(self.revealed)}" if self.revealed else ""
        return f"line {self.line}: {how} -> {clean(self.value, 100)!r} ({sure}{hidden})"


# ----------------------------------------------------------------------------- D. constant folding


@dataclass(frozen=True)
class Value:
    v: str | int
    definite: bool = True
    methods: frozenset = frozenset()
    literals: tuple = ()

    def combine(self, other: "Value", v, method: str | None = None) -> "Value":
        m = self.methods | other.methods | ({method} if method else set())
        return Value(v, self.definite and other.definite, frozenset(m), self.literals + other.literals)


CONSTANTS = {"vbcrlf": "\r\n", "vbnewline": "\r\n", "vbcr": "\r", "vblf": "\n", "vbtab": "\t",
             "vbnullstring": "", "vbnullchar": "\0", "vbback": "\b"}


class Fold:
    """Evaluate constant expressions over a token slice; never executes anything."""

    # binary operator -> precedence (higher binds tighter)
    PREC = {"xor": 1, "or": 2, "and": 3, "&": 4, "+": 5, "-": 5, "mod": 6, "\\": 7, "*": 8, "^": 10}

    def __init__(self, toks: list[Tok], env: dict[str, Value]):
        self.toks, self.env, self.pos, self.depth = toks, env, 0, 0

    def peek(self) -> Tok | None:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def op_name(self, t: Tok | None) -> str | None:
        if t is None:
            return None
        if t.kind == "op" and t.text in self.PREC:
            return t.text
        if t.kind == "id" and t.value in ("xor", "or", "and", "mod"):
            return t.value
        return None

    def expr(self, min_prec: int = 0) -> Value | None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            return None
        left = self.unary()
        while left is not None and (op := self.op_name(self.peek())) and self.PREC[op] >= min_prec:
            self.pos += 1
            right = self.expr(self.PREC[op] + 1)
            left = None if right is None else self.binary(op, left, right)
        self.depth -= 1
        return left

    def binary(self, op: str, a: Value, b: Value) -> Value | None:
        x, y = a.v, b.v
        if op == "&" or (op == "+" and isinstance(x, str) and isinstance(y, str)):
            s = str(x) + str(y)
            return a.combine(b, s, "concatenation") if len(s) <= MAX_FOLDED else None
        if not (isinstance(x, int) and isinstance(y, int)):
            return None
        try:
            v = {"+": lambda: x + y, "-": lambda: x - y, "*": lambda: x * y, "\\": lambda: int(x / y),
                 "mod": lambda: x - int(x / y) * y, "xor": lambda: x ^ y, "and": lambda: x & y, "or": lambda: x | y,
                 "^": lambda: x ** y if 0 <= y <= 64 else None}[op]()
        except ZeroDivisionError:
            return None
        if v is None or abs(v) > 2**63:
            return None
        return a.combine(b, v, "xor" if op == "xor" else "arithmetic")

    def unary(self) -> Value | None:
        t = self.peek()
        if t is not None and t.is_op("-"):
            self.pos += 1
            v = self.unary()
            return None if v is None or not isinstance(v.v, int) else Value(-v.v, v.definite, v.methods, v.literals)
        return self.primary()

    def args(self) -> list[Value | None] | None:
        """Parenthesised, comma-separated arguments; None if not a well-formed list."""
        if not (self.peek() and self.peek().is_op("(")):
            return None
        self.pos += 1
        out = []
        if self.peek() and self.peek().is_op(")"):
            self.pos += 1
            return out
        while True:
            out.append(self.expr())
            t = self.peek()
            if t is None or out[-1] is None:
                return None
            self.pos += 1
            if t.is_op(")"):
                return out
            if not t.is_op(","):
                return None

    def primary(self) -> Value | None:
        t = self.peek()
        if t is None:
            return None
        if t.kind == "str":
            self.pos += 1
            return Value(t.value, literals=(t.value,))
        if t.kind == "num":
            self.pos += 1
            return None if t.value is None else Value(t.value)
        if t.is_op("("):
            self.pos += 1
            v = self.expr()
            if v is None or not (self.peek() and self.peek().is_op(")")):
                return None
            self.pos += 1
            return v
        if t.kind != "id":
            return None
        self.pos += 1
        name = t.value
        if name in CONSTANTS:
            return Value(CONSTANTS[name])
        if self.peek() is not None and self.peek().is_op("("):
            args = self.args()
            return None if args is None else self.call(name, args)
        if name in self.env:
            return self.env[name]
        return None

    def call(self, name: str, a: list[Value]) -> Value | None:
        def mark(v, method: str) -> Value:
            definite = all(x.definite for x in a)
            lits = tuple(lit for x in a for lit in x.literals)
            return Value(v, definite, frozenset().union(*(x.methods for x in a)) | {method}, lits)

        s = [x.v for x in a]
        n = len(s)
        try:
            if name in ("chr", "chrw", "chrb") and n == 1 and isinstance(s[0], int):
                return mark(chr(s[0]), "chr") if 0 <= s[0] <= 0xFFFF else None
            if name in ("asc", "ascw") and n == 1 and isinstance(s[0], str) and s[0]:
                return mark(ord(s[0][0]), "asc")
            if not all(isinstance(x, (str, int)) for x in s):
                return None
            if name == "strreverse" and n == 1 and isinstance(s[0], str):
                return mark(s[0][::-1], "strreverse")
            if name in ("lcase", "ucase", "trim", "ltrim", "rtrim") and n == 1 and isinstance(s[0], str):
                f = {"lcase": str.lower, "ucase": str.upper, "trim": lambda x: x.strip(" "),
                     "ltrim": lambda x: x.lstrip(" "), "rtrim": lambda x: x.rstrip(" ")}[name]
                return mark(f(s[0]), "case/trim")
            if name in ("left", "right") and n == 2 and isinstance(s[0], str) and isinstance(s[1], int) and s[1] >= 0:
                return mark(s[0][: s[1]] if name == "left" else (s[0][-s[1]:] if s[1] else ""), "substring")
            if name == "mid" and n in (2, 3) and isinstance(s[0], str) and all(isinstance(x, int) for x in s[1:]) and s[1] >= 1:
                end = None if n == 2 else s[1] - 1 + s[2]
                return mark(s[0][s[1] - 1:end], "substring")
            if name == "replace" and n == 3 and all(isinstance(x, str) for x in s) and s[1]:
                if len(s[0]) + s[0].count(s[1]) * len(s[2]) > MAX_FOLDED:  # bound before building it
                    return None
                v = s[0].replace(s[1], s[2])
                return mark(v, "replace") if len(v) <= MAX_FOLDED else None
            if name == "len" and n == 1 and isinstance(s[0], str):
                return mark(len(s[0]), "len")
            if name == "space" and n == 1 and isinstance(s[0], int) and 0 <= s[0] <= 4096:
                return mark(" " * s[0], "space")
            if name == "string" and n == 2 and isinstance(s[0], int) and 0 <= s[0] <= 4096:
                c = chr(s[1]) if isinstance(s[1], int) and 0 <= s[1] <= 0xFFFF else (s[1][:1] if isinstance(s[1], str) else "")
                return mark(c * s[0], "string") if c else None
            if name == "cstr" and n == 1:
                return mark(str(s[0]), "cstr")
            if name in ("clng", "cint") and n == 1:
                return mark(int(s[0]), "cast") if isinstance(s[0], int) or str(s[0]).strip().lstrip("-").isdigit() else None
            if name == "hex" and n == 1 and isinstance(s[0], int):
                return mark(format(s[0] & 0xFFFFFFFF, "X"), "hex")
        except (ValueError, OverflowError):
            return None
        return None


def fold(toks: list[Tok], env: dict[str, Value] | None = None) -> Value | None:
    """The value of the whole token slice, or None if it is not a constant expression."""
    f = Fold(toks, env or {})
    v = f.expr()
    return v if v is not None and f.pos == len(toks) else None


def fold_runs(toks: list[Tok], env: dict[str, Value]) -> list[Value]:
    """Every maximal constant sub-expression of a statement (left to right), folded."""
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t.kind in ("str", "num") or (t.kind == "id" and (t.value in env or t.value in CONSTANTS
                                                            or (i + 1 < len(toks) and toks[i + 1].is_op("(")))):
            f = Fold(toks[i:], env)
            v = f.expr()
            if v is not None and f.pos > 0:
                out.append(v)
                i += f.pos
                continue
        i += 1
    return out


_HEX = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")
_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def decode_literal(text: str) -> tuple[str, str] | None:
    """(method, decoded text) for a hex or base64 literal that decodes to readable text."""
    candidates = []
    if _HEX.fullmatch(text):
        candidates.append(("hex-literal", binascii.unhexlify(text)))
    if _B64.fullmatch(text) and len(text) % 4 == 0:
        try:
            candidates.append(("base64-literal", base64.b64decode(text, validate=True)))
        except binascii.Error:
            pass
    for method, raw in candidates:
        for encoding in ("ascii", "utf-16-le"):
            try:
                decoded = raw.decode(encoding)
            except UnicodeDecodeError:
                continue
            if len(decoded) >= 8 and all(c.isprintable() or c in "\r\n\t" for c in decoded):
                return method, decoded
    return None


# ----------------------------------------------------------------------------- C. capabilities


def classify_object(name: str) -> str:
    n = name.strip().lower()
    n = n[4:] if n.startswith("new:") else n
    if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", n):
        n = "{" + n + "}"
    if n.startswith("winmgmts"):
        return "wmi-process" if "win32_process" in n else "wmi"
    for progid, kind in PROGIDS.items():
        if n == progid or (not progid.startswith("{") and n.startswith(progid + ".")):
            return kind
    return UNKNOWN


def split_args(toks: list[Tok], open_index: int) -> tuple[list[list[Tok]], int]:
    """Top-level arguments of the parenthesis at open_index, and the index after its ')'."""
    args, cur, depth, i = [], [], 0, open_index
    while i < len(toks):
        t = toks[i]
        if t.is_op("("):
            depth += 1
            if depth > 1:
                cur.append(t)
        elif t.is_op(")"):
            depth -= 1
            if depth == 0:
                args.append(cur)
                return [a for a in args if a or len(args) > 1], i + 1
            cur.append(t)
        elif t.is_op(",") and depth == 1:
            args.append(cur)
            cur = []
        else:
            cur.append(t)
        i += 1
    return args + [cur], i


def statement_args(toks: list[Tok], start: int) -> list[list[Tok]]:
    """Arguments after a callee at toks[start-1]: parenthesised, or a statement-style list."""
    if start < len(toks) and toks[start].is_op("("):
        return split_args(toks, start)[0]
    return _commas(toks[start:])


def _commas(toks: list[Tok]) -> list[list[Tok]]:
    out, cur, depth = [], [], 0
    for t in toks:
        depth += t.is_op("(") - t.is_op(")")
        if t.is_op(",") and depth == 0:
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    return out + [cur] if cur or out else out


@dataclass
class Context:
    """What the whole project tells the analysis of one block of code."""
    procedures: set[str] = field(default_factory=set)  # user procedure names (lower case)
    apis: dict[str, str] = field(default_factory=dict)  # declared name -> API (alias or name)
    consts: dict[str, Value] = field(default_factory=dict)  # module-level Const
    assigned: dict[str, set[str]] = field(default_factory=dict)  # Set name = <object kind>, project-wide
    created: set[str] = field(default_factory=set)  # every object kind any CreateObject/GetObject makes


@dataclass
class CodeAnalysis:
    capabilities: list[Capability] = field(default_factory=list)
    decoded: list[Decoded] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)  # every folded string value (bounded)

    def add(self, c: Capability) -> None:
        if c not in self.capabilities:
            self.capabilities.append(c)


class Analyser:
    def __init__(self, ctx: Context, locals_: set[str] = frozenset()):
        self.ctx, self.locals = ctx, set(locals_)
        self.env: dict[str, Value] = dict(ctx.consts)
        self.assignments: dict[str, int] = {}
        self.objects: dict[str, str] = {}
        self.with_stack: list[str | None] = []
        self.created: list[tuple[str, int]] = []
        self.out = CodeAnalysis()

    # --- objects

    def object_kind(self, name: str) -> str | None:
        if name in self.objects:
            return self.objects[name]
        kinds = self.ctx.assigned.get(name)
        if kinds and len(kinds) == 1 and UNKNOWN not in kinds and name not in self.locals:
            return next(iter(kinds))
        if name in OFFICE_OBJECTS:
            return "office-app"
        if name in ("vba", "interaction"):
            return "vba-library"
        return None

    def creation(self, name: str, args: list[list[Tok]], line: int) -> str:
        values = [fold(a, self.env) for a in args]
        texts = [v.v for v in values if v is not None and isinstance(v.v, str)]
        if name == "getobject" and texts and texts[0].lower().startswith(("winmgmts", "new:")):
            kind = classify_object(texts[0])
        elif name == "getobject":
            kind = classify_object(texts[1]) if len(texts) > 1 else UNKNOWN
        else:
            kind = classify_object(texts[0]) if texts and values and values[0] is not None else UNKNOWN
        self.created.append((kind, line))
        return kind

    def chain_kind(self, toks: list[Tok], line: int) -> str | None:
        """Kind of the object an expression like a, a.b(1).c, CreateObject(..).Get(..) denotes."""
        if not toks:
            return None
        pos = 0
        if toks[0].is_op("."):
            kind = self.with_stack[-1] if self.with_stack else None
        elif toks[0].kind == "id":
            name, pos = toks[0].value, 1
            if name in CREATORS and pos < len(toks) and toks[pos].is_op("("):
                args, pos = split_args(toks, pos)
                kind = self.creation(name, args, line)
            elif name == "new":
                type_name = "".join(t.text for t in toks[1:] if t.kind == "id" or t.is_op("."))
                return classify_object(type_name)
            else:
                kind = self.object_kind(name)
                if pos < len(toks) and toks[pos].is_op("("):
                    _, pos = split_args(toks, pos)
                    kind = "office-member" if kind == "office-app" else None
        else:
            return None
        while pos + 1 < len(toks) and toks[pos].is_op(".") and toks[pos + 1].kind == "id":
            member, pos = toks[pos + 1].value, pos + 2
            args = []
            if pos < len(toks) and toks[pos].is_op("("):
                args, pos = split_args(toks, pos)
            if kind == "vba-library" and member in CREATORS:
                kind = self.creation(member, args, line)
            elif kind == "vba-library" and member == "interaction":
                kind = "vba-library"
            elif kind == "wmi" and member == "get" and args:
                v = fold(args[0], self.env)
                kind = "wmi-process" if v is not None and "win32_process" in str(v.v).lower() else "wmi"
            elif kind in ("office-app", "office-member"):
                kind = "office-member"
            else:
                kind = None
        return kind if pos == len(toks) else None

    # --- statements

    def statement(self, toks: list[Tok], line: int) -> None:
        head = toks[0].value if toks[0].kind == "id" else None
        rest = toks[1:] if head in ("public", "private", "global", "friend", "static") else toks
        if rest and rest[0].is_id("declare"):
            return self.declare(rest, line)
        if rest and rest[0].is_id("const"):
            return self.const(rest[1:])
        if head == "with":
            self.with_stack.append(self.chain_kind(toks[1:], line))
        elif head == "end" and len(toks) > 1 and toks[1].is_id("with"):
            if self.with_stack:
                self.with_stack.pop()
        elif head in ("dim", "redim", "static") or rest is not toks:
            self.locals |= {t.value for i, t in enumerate(rest) if t.kind == "id" and (i == 1 or rest[i - 1].is_op(","))}
        self.assignment(toks, line)
        self.strings(toks, line)  # first, so a call can see the strings of its own statement
        self.calls(toks, line)

    def declare(self, toks: list[Tok], line: int) -> None:
        ids = [t.value for t in toks if t.kind == "id"]
        strs = [t.value for t in toks if t.kind == "str"]
        name = next((ids[i + 1] for i, v in enumerate(ids[:-1]) if v in ("sub", "function")), "")
        lib = strs[0] if strs else ""
        alias = strs[1] if "alias" in ids and len(strs) > 1 else name
        kind = APIS.get(alias.lower())
        if kind:
            self.out.add(Capability(kind, DEMONSTRATED, f"declares {alias} from {lib or 'a library'}", line))
        else:
            self.out.add(Capability("native-api", DEMONSTRATED, f"declares {clean(alias, 40)} from {clean(lib, 40)}", line))

    def const(self, toks: list[Tok]) -> None:
        for part in _commas(toks):
            if len(part) >= 3 and part[0].kind == "id":
                eq = next((i for i, t in enumerate(part) if t.is_op("=")), None)
                if eq is not None and (v := fold(part[eq + 1:], self.env)) is not None:
                    self.env[part[0].value] = v

    def assignment(self, toks: list[Tok], line: int) -> None:
        is_set = toks[0].is_id("set", "let")
        target = toks[1] if is_set and len(toks) > 1 else toks[0]
        eq = 2 if is_set else 1
        if target.kind != "id" or (not is_set and target.value in KEYWORDS) or len(toks) <= eq or not toks[eq].is_op("="):
            return
        name, rhs = target.value, toks[eq + 1:]
        self.assignments[name] = self.assignments.get(name, 0) + 1
        self.locals.add(name)
        kind = self.chain_kind(rhs, line) if rhs else None
        if kind is not None and kind not in ("office-member", "vba-library"):
            self.objects[name] = kind
            return
        if is_set:
            self.objects[name] = UNKNOWN
            return
        self.objects.pop(name, None)
        v = fold(rhs, self.env)
        if v is None:
            self.env.pop(name, None)
        else:  # a reassigned variable's value depends on control flow this analysis does not follow
            self.env[name] = Value(v.v, v.definite and self.assignments[name] == 1, v.methods | {"variable"}, v.literals)

    def calls(self, toks: list[Tok], line: int) -> None:
        for i, t in enumerate(toks):
            if t.kind != "id":
                continue
            prev = toks[i - 1] if i else None
            if prev is not None and prev.is_op("."):
                start = self.chain_start(toks, i - 1)
                receiver = self.chain_kind(toks[start:i - 1], line) if start < i - 1 else (
                    self.with_stack[-1] if self.with_stack else None)
                self.method(receiver, t.value, toks, i, line)
            else:
                self.function(t.value, toks, i, line)

    def chain_start(self, toks: list[Tok], dot: int) -> int:
        i = dot - 1
        while i >= 0:
            t = toks[i]
            if t.is_op(")"):
                depth = 0
                while i >= 0:
                    depth += toks[i].is_op(")") - toks[i].is_op("(")
                    if depth == 0:
                        break
                    i -= 1
                i -= 1
                continue
            if t.kind == "id":
                if i > 0 and toks[i - 1].is_op("."):
                    i -= 2
                    continue
                return i
            if t.is_op("."):
                return i
            break
        return i + 1

    def arg_texts(self, toks: list[Tok], start: int) -> list[str]:
        """Each argument's folded string value ("" where it is not a constant string)."""
        values = [fold(a, self.env) if a else None for a in statement_args(toks, start)]
        return [v.v if v is not None and isinstance(v.v, str) else "" for v in values]

    def first_arg_text(self, toks: list[Tok], start: int) -> str:
        return (self.arg_texts(toks, start) or [""])[0]

    def command_detail(self, command: str) -> str:
        if not command:
            return "command not constant"
        found = [s for s in INTERPRETERS + CRADLES if s in command.lower()]
        return f"command {clean(command, 80)!r}" + (f", uses {', '.join(found)}" if found else "")

    def execute(self, what: str, toks: list[Tok], start: int, line: int, status: str = DEMONSTRATED) -> None:
        command = self.first_arg_text(toks, start)
        self.out.add(Capability("execute", status, what, line, self.command_detail(command)))
        if "schtasks" in command.lower() and "/create" in command.lower():
            self.out.add(Capability("persistence", status, "schtasks /create in an executed command", line))

    def method(self, receiver: str | None, method: str, toks: list[Tok], i: int, line: int) -> None:
        start = i + 1
        if (receiver, method) in METHODS:
            kind, what = METHODS[(receiver, method)]
            if kind == "execute":
                return self.execute(what, toks, start, line)
            texts = self.arg_texts(toks, start)
            # the URL for an HTTP Open (its first argument is the verb), else the first argument
            target = next((t for t in texts if "://" in t), texts[0] if texts else "")
            self.out.add(Capability(kind, DEMONSTRATED, what, line, f"target {clean(target, 80)!r}" if target else ""))
            if method == "regwrite" and RUN_KEY.search(target):
                self.out.add(Capability("persistence", DEMONSTRATED, "RegWrite to a Run key (starts at logon)", line))
            if kind in ("write-file", "file-operation") and STARTUP.search(target):
                self.out.add(Capability("persistence", DEMONSTRATED, "writes into the Startup folder", line))
        elif method in SPECIFIC_METHODS:
            kind, what = SPECIFIC_METHODS[method]
            if kind == "execute":
                return self.execute(what, toks, start, line)
            self.out.add(Capability(kind, DEMONSTRATED, what, line))
        elif method in ("run", "exec") and receiver in (None, UNKNOWN) and "wscript.shell" in self.ctx.created:
            # The project creates WScript.Shell and this receiver could not be resolved: the object can
            # reach it as an argument, a collection item or a property, which this flow-insensitive
            # analysis does not follow. Treated as execution (fail closed), and labelled as inferred.
            return self.execute(f"{method.capitalize()} on an unresolved object in a project that creates "
                                "WScript.Shell (inferred: the object may be passed indirectly)", toks, start, line)
        elif method in AMBIGUOUS_METHODS and receiver in (None, UNKNOWN, "wmi"):
            kind, what = AMBIGUOUS_METHODS[method]
            if kind == "execute":
                return self.execute(what, toks, start, line, POSSIBLE)
            self.out.add(Capability(kind, POSSIBLE, what, line))
        elif method == "create" and receiver in (None, UNKNOWN, "wmi") and self.mentions("win32_process"):
            self.execute("Create on an object in a procedure that names Win32_Process", toks, start, line)
        elif method == "executeexcel4macro":
            self.function("executeexcel4macro", toks, i, line)
        elif method in FUNCTIONS and method in ("vbproject", "vbcomponents", "codemodule", "addfromstring", "insertlines"):
            self.out.add(Capability(*FUNCTIONS[method], DEMONSTRATED, line))
        elif method == "visible" and len(toks) > i + 2 and toks[i + 1].is_op("=") and toks[i + 2].is_id("false"):
            self.out.add(Capability("hide-application", DEMONSTRATED, "hides the application window", line))
        elif receiver == "vba-library" and method in ("shell", "macscript"):
            self.function(method, toks, i, line, qualified=True)

    def mentions(self, token: str) -> bool:
        return any(token in s.lower() for s in self.out.strings)

    def function(self, name: str, toks: list[Tok], i: int, line: int, qualified: bool = False) -> None:
        nxt = toks[i + 1] if i + 1 < len(toks) else None
        is_call = nxt is not None and not nxt.is_op(".", "=", ",", ")", ":=") and (
            nxt.is_op("(") or i == 0 or toks[i - 1].is_id("call") or qualified)
        if name in ("shell", "macscript", "applescripttask"):
            if not is_call:
                return
            if not qualified and (name in self.ctx.procedures or name in self.locals):
                return self.execute(f"{name} is called, but a user procedure or variable of that name shadows "
                                    "the built-in", toks, i + 1, line, POSSIBLE)
            what = {"shell": "Shell starts a program", "macscript": "MacScript runs an AppleScript",
                    "applescripttask": "AppleScriptTask runs an AppleScript"}[name]
            return self.execute(what, toks, i + 1, line)
        if name == "executeexcel4macro" and nxt is not None:
            macro = self.first_arg_text(toks, i + 1)
            if re.search(r"\b(EXEC|CALL|REGISTER)\s*\(", macro, re.I):
                return self.out.add(Capability("execute", DEMONSTRATED, "ExecuteExcel4Macro runs an Excel 4.0 "
                                               "function that starts a program or calls a DLL", line,
                                               f"macro {clean(macro, 80)!r}"))
            return self.out.add(Capability("execute", POSSIBLE, "ExecuteExcel4Macro with a macro that is not a "
                                           "constant without EXEC/CALL/REGISTER", line, f"macro {clean(macro, 80)!r}"))
        if name == "ddeinitiate" and nxt is not None:
            app = self.first_arg_text(toks, i + 1)
            if any(s in app.lower() for s in INTERPRETERS):
                return self.execute("DDEInitiate with a command interpreter as the application", toks, i + 1, line)
            return self.out.add(Capability("dde", DEMONSTRATED, "DDEInitiate opens a DDE channel", line))
        if name == "callbyname" and nxt is not None:
            args = statement_args(toks, i + 1)
            if len(args) >= 2 and (m := fold(args[1], self.env)) is not None and isinstance(m.v, str):
                # CallByName object, "Method", VbMethod, arguments...: the arguments start at the fourth
                rest = [t for a in args[3:] for t in a + [Tok("op", ",")]][:-1]
                self.method(self.chain_kind(args[0], line), m.v.lower(), rest, -1, line)
            return
        if name == "open" and i == 0 and any(t.is_id("output", "append", "binary") for t in toks):
            path = fold(toks[1:next((k for k, t in enumerate(toks) if t.is_id("for")), len(toks))], self.env)
            target = path.v if path is not None and isinstance(path.v, str) else ""
            self.out.add(Capability("write-file", DEMONSTRATED, "Open ... For Output/Append/Binary writes a file", line))
            if STARTUP.search(target):
                self.out.add(Capability("persistence", DEMONSTRATED, "writes into the Startup folder", line))
            return
        if name in FUNCTIONS and (is_call or name in ("vbproject", "vbcomponents", "codemodule")):
            self.out.add(Capability(*FUNCTIONS[name], DEMONSTRATED, line))

    def strings(self, toks: list[Tok], line: int) -> None:
        for v in fold_runs(toks, self.env):
            if not isinstance(v.v, str):
                continue
            if len(self.out.strings) < 256:
                self.out.strings.append(v.v)
            revealed = tuple(s for s in sensitive_in(v.v) if not any(s in lit.lower() for lit in v.literals))
            methods = tuple(sorted(v.methods - {"variable"}))
            d = Decoded(line, v.v, methods or ("variable",), v.definite, revealed)
            if (revealed or (set(methods) & HIDING and len(v.v) >= 4)) and d not in self.out.decoded:
                self.out.decoded.append(d)
        for t in toks:
            if t.kind == "str" and (d := decode_literal(t.value)):
                method, text = d
                self.out.decoded.append(Decoded(line, text, (method,), False, tuple(sensitive_in(text))))

    def finish(self) -> CodeAnalysis:
        executes = any(c.kind == "execute" and c.status == DEMONSTRATED for c in self.out.capabilities)
        for kind, line in dict.fromkeys(self.created):
            if kind in EXEC_OBJECTS and not executes:
                self.out.add(Capability("execute", POSSIBLE, f"creates {kind}, whose {EXEC_OBJECTS[kind]} method "
                                        "executes commands; no such call was resolved", line))
        mentioned = [s for s in self.out.strings for i in INTERPRETERS + CRADLES if i in s.lower()]
        if mentioned and not any(c.kind == "execute" for c in self.out.capabilities):
            self.out.add(Capability("interpreter-string", DEMONSTRATED, "a string names a command interpreter "
                                    "or download command", 0, f"{clean(mentioned[0], 80)!r}"))
        return self.out


def analyse_code(lines: list[tuple[int, str]], ctx: Context | None = None, locals_: set[str] = frozenset()) -> CodeAnalysis:
    """Capabilities and decoded strings of one block of logical lines (a procedure or module text)."""
    a = Analyser(ctx or Context(), locals_)
    for n, text in lines:
        for stmt in statements(tokenize(text)):
            a.statement(stmt, n)
    return a.finish()


def context(modules: list[tuple[str, list[tuple[int, str]]]], procedures: set[str]) -> Context:
    """Project-wide facts: Const values, declared APIs, and what every Set assigns (first pass)."""
    ctx = Context(procedures=set(procedures))
    probe = Analyser(ctx)
    for _, lines in modules:
        for n, text in lines:
            for stmt in statements(tokenize(text)):
                head = stmt[0].value if stmt[0].kind == "id" else None
                rest = stmt[1:] if head in ("public", "private", "global") else stmt
                if rest and rest[0].is_id("const"):
                    probe.const(rest[1:])
                elif rest and rest[0].is_id("declare"):
                    ids = [t.value for t in rest if t.kind == "id"]
                    strs = [t.value for t in rest if t.kind == "str"]
                    name = next((ids[i + 1] for i, v in enumerate(ids[:-1]) if v in ("sub", "function")), "")
                    ctx.apis[name] = strs[1] if "alias" in ids and len(strs) > 1 else name
                elif stmt[0].is_id("set") and len(stmt) > 3 and stmt[1].kind == "id" and stmt[2].is_op("="):
                    kind = probe.chain_kind(stmt[3:], n) or UNKNOWN
                    ctx.assigned.setdefault(stmt[1].value, set()).add(kind)
                for i, t in enumerate(stmt[:-1]):  # objects created anywhere, also as an argument
                    if t.kind == "id" and t.value in CREATORS and stmt[i + 1].is_op("("):
                        probe.creation(t.value, split_args(stmt, i + 1)[0], n)
    ctx.consts = {k: v for k, v in probe.env.items()}
    ctx.created = {kind for kind, _ in probe.created}
    return ctx


# ----------------------------------------------------------------------------- XLM


def analyse_xlm(text: str) -> tuple[list[str], list[Capability]]:
    """Excel 4.0 macro sheets, from the extractor's BIFF record listing: names that start them
    automatically, and macro functions that run programs or call DLLs. Not evaluated."""
    entries = sorted({m.group() for m in re.finditer(r"(?i)\bauto_(open|close|activate)\w*", text)})
    caps = [Capability("execute", DEMONSTRATED, f"Excel 4.0 macro function {m.group(1)}", 0)
            for m in re.finditer(r"\b(EXEC|CALL|REGISTER)\b", text)]
    caps += [Capability("download", DEMONSTRATED, "Excel 4.0 macro names URLDownloadToFile", 0)
             for _ in re.finditer(r"(?i)URLDownloadToFile", text)]
    return entries, list(dict.fromkeys(caps))


# ----------------------------------------------------------------------------- extraction


@dataclass(frozen=True)
class Extraction:
    vba: bool = False
    xlm: bool = False
    modules: tuple[tuple[str, str], ...] = ()  # (module name, source); XLM text under XLM_MODULE
    error: BaseException | None = None  # extraction failed (the Office scanner fails closed)
    too_large: bool = False


XLM_MODULE = "xlm_macro"


@functools.lru_cache(maxsize=4)
def extract(blob: bytes, label: str) -> Extraction:
    """VBA and XLM source of one OLE VBA container, via oletools' extractor (parsing only).
    Cached: the Office scanner and the call-graph scanner read the same bytes in one worker."""
    parser = None
    try:
        parser = VBA_Parser(label, data=blob)
        xlm = bool(parser.detect_xlm_macros())
        vba = bool(parser.detect_vba_macros())
        if not (vba or xlm):
            return Extraction()
        modules, total = [], 0
        for _, stream, name, code in parser.extract_macros():
            total += len(code or "")
            if total > MAX_SOURCE_BYTES:
                return Extraction(vba, xlm, tuple(modules), too_large=True)
            is_xlm = stream == XLM_MODULE or name == "xlm_macro.txt"
            # olevba names a module by its export file name (Module1.bas, ThisDocument.cls); the
            # VBA name, which qualified calls (Module1.Helper) use, is without the extension.
            name = re.sub(r"(?i)\.(bas|cls|frm|vba)$", "", name or "module")
            modules.append((XLM_MODULE if is_xlm else clean(name, 40), code or ""))
        return Extraction(vba, xlm, tuple(modules))
    except Exception as e:  # noqa: BLE001 - reported to the caller, which decides how to fail closed
        return Extraction(error=e)
    finally:
        if parser is not None:
            parser.close()
