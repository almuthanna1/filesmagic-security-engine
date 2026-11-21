# FilesMagic Unified Security Engine: capstone technical guide

NIU CSCI 499 capstone. This guide explains, detector by detector, what analysis the engine
performs, which code performs it, and where its limits are. Its examples are real engine output
on inert synthetic inputs: the scripts that produced them are named, and nothing in them can run.
Measured results are in [regression-report.md](regression-report.md). The Conversion Engine and
frontend plan is in [integration-plan.md](integration-plan.md).

## 0. The engine in one page

```
upload bytes ──> FastAPI /scan (app/main.py): size limit, scan token, engine=unified
                    │
                    ▼
          isolated worker process (app/worker.py)
          audit hook, Linux namespaces/capabilities/rlimits, timeout
                    │   runs the 9 scanners of app/engine/__init__.py in order
                    ▼
  signatures │ office │ pdf │ custom │ pdf-chains │ pdf-integrity │ vba-chains │ ooxml-links │ word-fields
                    │   each returns findings, None (not applicable), or raises (failed)
                    ▼
          correlate() (app/engine/correlate.py): merge, qualify or replace overlapping findings
                    │
                    ▼
          decision (app/decision): verdict + authorization + reasons
          SAFE / SUSPICIOUS / MALICIOUS / UNABLE_TO_SCAN
                    │
                    ▼
          signed receipt (app/receipts.py) bound to the file's SHA-256, the commit and the roster
```

The verdict rules (`app/decision/__init__.py`) are fixed:

- any HIGH or CRITICAL finding → **MALICIOUS** (deny);
- otherwise any LOW or MEDIUM finding → **SUSPICIOUS** (converted only with explicit consent);
- a failed applicable scanner, or a coverage gap → **UNABLE_TO_SCAN** (consent only for documented
  document reasons, otherwise deny);
- **SAFE** only when every applicable scanner completed and none found anything above INFO. SAFE
  means "no configured indicator found", not "no malware".

**Third-party code.** Third-party libraries only *parse*:

- pypdf: PDF objects;
- olefile and oletools' `VBA_Parser`: OLE streams and MS-OVBA decompression;
- zipfile and zlib;
- defusedxml;
- msoffcrypto: the encryption header only.

Every decision about whether something is risky is made by code in this repository. The check is
`tests/test_api_engines.py::test_the_service_never_imports_a_retired_detection_dependency`:

- YARA-X is never imported;
- the only name imported from `oletools.olevba` is `VBA_Parser`;
- olevba's `analyze_macros` and `VBA_Scanner` are never called.

**What "custom" means here.** A detector counts as ours only when it computes something the
parser does not:

- a parser gives a token stream, an object graph or a list of ZIP entries;
- our code decides what in that structure is risky, under which conditions, and with what
  certainty.

Each section below names that computation explicitly (item 6).

---

## 1. Signature matcher (`signatures`)

1. **Threat.** Byte patterns that mark risky content in any file, whatever its declared type:
   - a PDF `/Launch` action, or JavaScript with an automatic trigger;
   - VBA projects in OLE and OOXML files;
   - RTF `\objupdate` and `DDEAUTO`;
   - SVG scripts;
   - native executables (PE, ELF).

   It is the independent second signal that still fires when a structural parser rejects a file.
2. **Algorithm.** A rule is a set of patterns (literal or regular expression) plus a boolean
   condition over where and how often they match. The matcher:
   - evaluates conditions lazily, with short-circuit, after a cheap `applies` header check;
   - searches a pattern only when a condition asks for it.

   Why this design: it reproduces the semantics of the YARA rules it replaced (the same rule IDs,
   so the same verdicts), using only `bytes.find` and `re`. The rules need only a small part of
   YARA, so a full YARA implementation would add code without adding detection.
3. **Input and output.** Input: the raw bytes. The filename is ignored. Output: one `Finding` per
   matching rule, with the rule's severity and evidence that lists match offsets, never content.
   A rule-set error or the deadline raises `SignatureError`, and the scan becomes UNABLE_TO_SCAN.
4. **Functions** (`app/engine/signatures.py`):
   - `literal`, `regex`: build patterns. `nocase` is ASCII case folding; `wide` is UTF-16LE.
   - `_next_start`, `find_all`: find matches.
   - `Matches`: lazy per-pattern cache, `within`, `count`, `u16`/`u32`.
   - `validate`: rejects incomplete rules, which leaves the scanner not ready.
   - `SignatureScanner.scan`, `evidence`, `ruleset_hash`.

   The rules are in `app/engine/signature_rules.py`. Each one quotes the YARA text it ports.
5. **Data structures.** Each pattern keeps a sorted list of match *start* offsets, capped at
   `MAX_MATCHES_PER_PATTERN` (1000). Matches may overlap: the search restarts one byte after the
   previous *start*, so `"aa"` occurs twice in `"aaa"`. `re.finditer` would silently skip
   overlapping matches.
6. **Original or reused.**
   - Original: the matcher, the condition model, the overlap and saturation semantics, the
     4,095-byte regex window, and the refined JavaScript rule
     (`ENGINE_PDF_JavaScript_With_Automatic_Trigger`), which stays silent only when the bytes
     prove every trigger is user-initiated.
   - Reused: Python's `re` engine and the rule *ideas* from the former `.yar` files.
7. **References.** The YARA documentation: string modifiers `nocase` and `wide`, `$x in (a..b)`,
   `#x`, `uint16`/`uint32`. ISO 32000-1 §7.2.2 (PDF delimiters) and §12.6.3 (trigger events).
   PE/COFF and ELF header layouts.
8. **Complexity and limits.**
   - Per pattern: at most 1000 restarted searches, each O(n), so the worst case is O(1000·n) per
     pattern.
   - A regex match is limited to a 4,095-byte window.
   - The scan checks a 10 s deadline between searches.
   - The input itself is limited by the API's upload limit.
   - Measured: 48.8 ms for 5,328 inputs (1.79 MB), with a Python heap peak of 1.1 MiB.
9. **False-positive risks.** The rules see raw bytes only. A PDF that mentions `/JavaScript` and
   `/OpenAction` in a text string can match. That is why these rules are MEDIUM or LOW, and why
   correlation merges the JavaScript signature into the chain finding when the parsed chain
   confirms it.
10. **Limitations.** The rules cannot see:
    - compressed content (FlateDecode streams, deflated OOXML parts);
    - escaped PDF names (`/J#61vaScript`).

    Those cases are covered by the PDF, custom and Office parsers. A single `re.search` cannot be
    interrupted, so the rules are reviewed for linear behaviour and timed on adversarial inputs.
11. **Tests and results.**
    - `tests/test_signatures.py` (50 tests): semantics, every rule positive and negative, the
      deadline, fail-closed behaviour, and adversarial timing.
    - Differential test against YARA-X (development-only oracle): **5,328 of 5,328 inputs agree**,
      and every rule fires at least once.
12. **What to tell Dr. Haque.** "We replaced YARA-X with a 250-line matcher that implements
    exactly the YARA semantics our rules use: overlapping start offsets, `nocase`, `wide`, offset
    ranges, counts that saturate at the cap, and a match-length window. We did not trust our own
    reading of YARA. We ran YARA-X itself as an oracle on more than 5,000 inputs, built to hit
    every boundary, and the two agree on all of them. YARA-X's raw matching is about six times
    faster than ours. Because the old scanner built a new YARA scanner for every file, our version
    is faster per file in this service."

**Inert example.** The input is a `.docx` whose ZIP contains a member named `word/vbaProject.bin`,
with placeholder bytes. Rule `OOXML_VBA_Macros`: `applies` checks that the file starts with
`PK\x03\x04`, and the literal `vbaProject.bin` is found. Result:
`[signatures] OOXML_VBA_Macros MEDIUM: Office Open XML (ZIP-based) document contains a VBA macro
project (vbaProject.bin).` (case 7 of `evaluation/cases`).

---

## 2. VBA behaviour analysis (`office` macro findings; `app/engine/vba_analysis.py`)

1. **Threat.** Macros that run without being started by name and then execute programs, download
   files, inject code or persist. Often the strings are hidden (`StrReverse`, `Chr` arithmetic,
   `Replace`) from keyword scanners.
2. **Algorithm.** Static analysis of the VBA source in four stages:
   - **A. Lines and tokens.** Continuations (` _`) are joined; comments (`'`, `Rem`) and string
     literals are tokenized; statements are split at `:` and at one-line `If ... Then`.
   - **B. Entry points.** A table of procedure names Office runs by itself, each with a trigger
     kind: document lifecycle events, ActiveX events, and user events.
   - **C. Capabilities in context.** The *receiver* decides whether a call is dangerous.
     - `Shell` is execution only if it is not shadowed by a user procedure.
     - `.Run` is execution on `WScript.Shell`; on `Application`, `Run` only starts a macro.
     - On an unknown object, `.Run` is only POSSIBLE.

     Objects are tracked from `CreateObject`/`GetObject`/`New`, through `Set`, `With` blocks and
     chained calls.
   - **D. Constant folding.** A recursive-descent evaluator for constant expressions only. A
     folded string "reveals" something when it contains a sensitive token that none of its source
     literals contains alone. That is the obfuscation indicator.

   Why: keyword lists (olevba) cannot tell `Application.Run` from `WScript.Shell.Run`, a constant
   named `vbHide` from a call, or a user procedure named `Shell` from the built-in. Folding finds
   names that were built at runtime to evade keyword scans, without executing anything.
3. **Input and output.** Input: the module sources extracted by `extract()`. Output: entries
   (procedure plus trigger), capabilities (kind, DEMONSTRATED or POSSIBLE, line, constant
   argument) and decoded strings. The Office scanner maps them to `OFFICE_MACROS_PRESENT`,
   `OFFICE_MACRO_AUTOEXEC`, `OFFICE_MACRO_DANGEROUS_CAPABILITY`, `OFFICE_MACRO_SUSPICIOUS_KEYWORDS`,
   `OFFICE_MACRO_OBFUSCATION` and `OFFICE_MACRO_AUTOEXEC_EXECUTION` (HIGH).
4. **Functions** (`app/engine/vba_analysis.py`):
   - `logical_lines`, `tokenize`, `statements`;
   - `entry_trigger`;
   - the `Analyser` class (capabilities and object tracking);
   - `Fold`, `fold`, `fold_runs`, `decode_literal`;
   - `classify_object`, `context`, `analyse_code`, `analyse_xlm`, `extract`.

   Callers: `app/scanners/office.py` (`vba_findings`, `macro_findings`) and `app/engine/vba_chains.py`.
5. **Data structures.**
   - Token records (`Tok`), and per-procedure symbol sets for shadowing.
   - An object-kind map from variable to ProgID class. It is flow-insensitive: a module-level
     variable resolves to a kind only if every `Set` in the project assigns that kind.
   - The fold evaluator returns a `Value(v, definite, methods, literals)`. `definite` means the
     value was built from literals and constants only.
6. **Original or reused.**
   - Original: the tokenizer, the entry table, every capability rule, receiver tracking, the
     folding evaluator, and the "reveals" test.
   - Reused: oletools' `VBA_Parser.extract_macros` only, for MS-OVBA decompression and OLE stream
     walking. olevba's AUTOEXEC table is used in a test, to prove no baseline trigger was lost.
7. **References.**
   - [MS-OVBA] (VBA project storage and compression) and [MS-VBAL] (VBA language: tokens, line
     continuation, `Rem`, statement separators).
   - Microsoft documentation of Word Auto macros and of Excel `Auto_Open`/`Workbook_Open`.
   - The olevba source, for comparison only.
8. **Complexity and limits.** Tokenizing is linear in the source. The bounds are:
   - logical lines of at most 64 Ki characters;
   - folded strings of at most 64 Ki characters (`Replace` checks this *before* it builds the
     result);
   - expression depth of at most 48;
   - at most 8 MiB of source per document.

   Unsupported syntax stops a fold; it never guesses.
9. **False-positive risks.** A legitimate macro with a `Document_Open` handler that really calls
   `Shell` is reported HIGH. The engine reports the capability; it does not judge intent. The
   baseline's keyword false positives (§2 of the regression report) are removed.
10. **Limitations.**
    - No data flow through branches, loops, procedure arguments, cell values or document variables.
    - No P-code analysis: VBA stomping is not detected.
    - Excel 4.0 (XLM) macros: only function names are detected.
    - Objects obtained in ways the analysis does not model are "unknown" (POSSIBLE), with one
      fail-closed exception: `Run`/`Exec` on an unknown object counts as execution (DEMONSTRATED)
      when the project creates `WScript.Shell` anywhere, since the object may reach it as an
      argument or a collection item (`vba_analysis.Analyser.method`, `Context.created`).
11. **Tests and results.**
    - `tests/test_vba_analysis.py` (59 tests), including parity with olevba's entry tables.
    - `tests/test_office.py` (72 tests).
    - `tests/test_vba_end_to_end.py` (8 tests, on real MS-OVBA projects, through the isolated
      worker).
    - VBA case matrix: 16 of 16 outcomes as intended; 5 baseline false positives removed.
12. **What to tell Dr. Haque.** "olevba decides by keywords: if the word 'Run' appears, the macro
    'may run an executable'. We parse the VBA, follow which object each method is called on, and
    evaluate constant string expressions statically. So `CreateObject(StrReverse("llehS.tpircSW")).Run`
    is recognised as `WScript.Shell.Run`, and `Application.Run "Helper"` is not treated as
    execution. Nothing is ever executed."

**Inert example** (VBA case v09):

```vba
Sub Document_Open()
    Set o = CreateObject(StrReverse("llehS.tpircSW"))
    o.Run "placeholder"
End Sub
```

Engine output:

- `fold(StrReverse("llehS.tpircSW"))` gives `Value(v='WScript.Shell', definite=True,
  methods={'strreverse'}, literals=('llehS.tpircSW',))`.
- `wscript.shell` is in the folded value but in none of its literals, so it is revealed:
  `OFFICE_MACRO_OBFUSCATION LOW: ... line 2: strreverse -> 'WScript.Shell' (definite; reveals
  wscript, wscript.shell)`.
- `o` is now a `WScript.Shell` object, so `o.Run` is DEMONSTRATED execution:
  `OFFICE_MACRO_DANGEROUS_CAPABILITY MEDIUM: ... execute: WScript.Shell.Run starts a program or
  command (line 3, command 'placeholder')`.
- `Document_Open` is an entry point, so the result is `OFFICE_MACRO_AUTOEXEC_EXECUTION HIGH`.

A second fold that combines three methods: `Chr(87) & "Script." & Replace("ShXll", "X", "e")` gives
`'WScript.Shell'` (methods: chr, concatenation, replace). A fold that depends on a variable, as in
`x & "a"` with unknown `x`, returns `None`: no guess.

---

## 3. VBA call graph (`vba-chains`; `app/engine/vba_chains.py`)

1. **Threat.** The same as §2, made precise: does the code Office starts automatically actually
   *reach* the dangerous operation? A macro can also have both properties without any connection
   between them.
2. **Algorithm.**
   - Build a graph with procedures as nodes and calls as edges. Each edge is DEMONSTRATED (a
     statement or `Call` target, `Module.Name`, `AddressOf`, a literal name in
     `Run`/`OnTime`/`CallByName`) or POSSIBLE (the name is also a variable, or `obj.Name` on a
     non-module).
   - Run a breadth-first search from every entry. Each entry ends as **linked** (a demonstrated
     path to a demonstrated capability), **no-path**, or **undetermined**.

   Why: the Office scanner's HIGH rule says "entry and capability in the same project". The graph
   gives the reviewer the *path*, and "undetermined" keeps uncertainty explicit instead of
   rounding it either way.
3. **Input and output.** Input: the extracted modules. Output:
   - `ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY` (HIGH, with the path);
   - `ENGINE_VBA_NO_CALL_PATH` (INFO);
   - `ENGINE_VBA_CALL_PATH_UNDETERMINED` (INFO);
   - `ENGINE_VBA_SOURCE` (INFO excerpts).
4. **Functions:** `parse`, `declared`, `link`, `search`, `_path`, `analyse`, `analyse_cached`,
   `projects`, `scan`. The findings are built in `correlate.vba_findings`.
5. **Data structures.** A `Procedure` with outgoing edges labelled DEMONSTRATED or POSSIBLE. BFS
   with a parent map (`_path` rebuilds the path). The names of module procedures are qualified
   (`Module1.Tool`).
6. **Original or reused.** The graph, the call resolution, the BFS and the three-way outcome are
   original. The capabilities come from §2 (also ours). Extraction is the only reused part.
7. **References.** Standard BFS (Cormen et al., *Introduction to Algorithms*, ch. 20/22). [MS-VBAL]
   for `Call`, `AddressOf` and qualified names.
8. **Complexity and limits.** O(V+E) per entry, so O(entries·(V+E)) in total. At most 20,000
   procedures, and the source limit of §2.
9. **False-positive risks.** A demonstrated path to a demonstrated capability is a fact about the
   source. If the capability is legitimate (an add-in that opens a help file with `Shell`), the
   finding is still HIGH.
10. **Limitations.**
    - "no-path" describes the source only. Office may run P-code instead, so correlation **never
      lowers** a finding on "no-path".
    - Dynamic calls (`CallByName` with a computed name, `Evaluate`) make the outcome undetermined.
11. **Tests and results.** `tests/test_vba_chains.py` (62 tests). Rebuild fixes:
    - qualified calls across modules now resolve (v02);
    - a user procedure named `Shell` gives POSSIBLE, not HIGH (v08).
12. **What to tell Dr. Haque.** "We build a call graph of the macro project and search from every
    procedure Office runs automatically. We report the actual path, such as `AutoOpen -> Tool ->
    Shell`. When we cannot be sure, we say 'undetermined' instead of guessing. We never use 'no
    path found' to downgrade a finding, because the compiled P-code may differ from the source."

**Inert example** (VBA case v01):

```vba
Sub AutoOpen()
    Tool
End Sub
Sub Tool()
    Shell "placeholder"
End Sub
```

The edge `Module1.AutoOpen -> Module1.Tool` is DEMONSTRATED, because `Tool` is a statement target.
`Tool` has a DEMONSTRATED `execute`. The search gives `ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY HIGH:
... Module1.AutoOpen -> Module1.Tool (execute: Shell starts a program (line 5, command
'placeholder'))`.

In v08 the project also declares `Sub Shell(s)`. The call is then only POSSIBLE, and the outcome is
`ENGINE_VBA_CALL_PATH_UNDETERMINED INFO: ... possible path Module1.AutoOpen -> Module1.Shell ...`.

---

## 4. C1: PDF name obfuscation (`custom`; `app/scanners/custom/pdf.py`, `pdf_syntax.py`)

1. **Threat.** PDF names may encode any byte as `#xx`. `/J#61vaScript` *is* `/JavaScript` to a
   reader, but it defeats every plain-text search, including byte signatures.
2. **Algorithm.** Our own lexer, written from ISO 32000-1 §7.2–7.5.
   - It reads the file sequentially, skips strings and comments correctly, and inflates
     FlateDecode object streams.
   - It decodes every name that contains `#`, and counts the escapes that were *unnecessary*: a
     byte that could have been written plainly.
   - An active-content name (JavaScript, JS, Launch, OpenAction, AA, EmbeddedFile, URI, ...)
     written with unnecessary escapes is the signal.

   Why: generators escape only what must be escaped (a space, a delimiter, `#`, or a byte outside
   `!`–`~`). An unnecessary escape exists only to hide something, so it is a high-precision
   indicator.
3. **Input and output.** Input: the raw PDF bytes. Output:
   - `CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME` (MEDIUM);
   - `CUSTOM_PDF_UNNECESSARY_NAME_ESCAPES` (INFO);
   - `CUSTOM_PDF_COVERAGE_LIMITED` (INFO).

   A file with no object, or with an unterminated string or stream, raises `CustomScanError`
   (invalid_structure): fail closed.
4. **Functions:** `pdf_syntax.tokens`, `decode_name`, `_string_end`, `inflate`, `parse`
   (`PdfSyntax`), and `pdf.name_obfuscation`, `coverage`, `analyse`.
5. **Data structures.**
   - One compiled regex token pattern. Ordinary names are skipped inside the regex engine, which
     keeps a 10 MB file within the CPU budget.
   - An object index (`_Index`), so each token's location is reported as "object N G".
   - Counters of what was not inspected, and why.
6. **Original or reused.** Everything is original. Only zlib is reused, for inflation; pypdf is
   not used.
7. **References.** ISO 32000-1:2008 §7.3.5 (names), §7.3.4.2 (literal strings), §7.5.7 (object
   streams).
8. **Complexity and limits.** One linear pass over the file and over each inflated object stream.
   The limits are:
   - at most 50,000 streams;
   - at most 50,000 escaped names;
   - at most 20 MiB decoded per stream, and 32 MiB per document.
9. **False-positive risks.** Very low: necessary escapes (`/Arial#20Bold`) are never counted. An
   unusual generator that escapes everything would produce INFO findings for ordinary names, and
   MEDIUM only for active names.
10. **Limitations.**
    - Object streams with other filters, filter chains, or an indirect filter are counted as not
      inspected.
    - An encrypted document's object streams are counted as not inspected.
    - PDF 1.0/1.1 (where `#` was an ordinary character) is not handled.
11. **Tests and results.** `tests/test_custom_pdf.py` (39 tests). Cases 3 and 4 (escaped, and
    escaped inside an object stream) are detected; the signatures do not see them.
12. **What to tell Dr. Haque.** "The PDF standard allows any character in a name to be written as
    `#` plus two hex digits. Real generators use this only when they must, so `/J#61vaScript` has
    no purpose except to hide the word JavaScript from scanners. Our lexer decodes names, counts
    the unnecessary escapes, and reports where they are, including inside compressed object
    streams that a byte search cannot see."

**Inert example.** `fx.obfuscated_javascript_pdf()` writes `/S /J#61vaScript /J#53 (...)`. Result:
`CUSTOM_PDF_OBFUSCATED_ACTIVE_NAME MEDIUM: PDF writes 2 active-content name(s) with unnecessary
#-escapes ... '/J#61vaScript' decodes to /JavaScript (1x); '/J#53' decodes to /JS (1x). Location:
object 5 0.` No signature fires on this file, because the escaped names defeat the byte patterns.

---

## 5. C4–C6: OOXML declaration, relationships, container (`custom`; `ooxml.py`, `ooxml_package.py`)

1. **Threat.** OOXML packages that misrepresent themselves:
   - macro code inside a package declared macro-free (a `.docx` carrying `vbaProject.bin`);
   - parts no relationship reaches, which can hide data;
   - ZIP structures that different readers interpret differently.
2. **Algorithm.** Three independent methods over one parsed package:
   - **C4** compares the declared main content type and family with the parts actually present.
   - **C5** builds the relationship graph from `_rels/.rels` and searches it to find the
     reachable parts. It reports unreachable *binary* parts, duplicate Ids, and dangling
     references.
   - **C6** compares each local ZIP header with the central directory: impossible sizes,
     overlapping entries, unsupported methods. It reads metadata only and decompresses nothing.

   Why: Office resolves a package through content types and relationships, never through the
   filename. So the inconsistencies that matter are between those structures and the bytes.
3. **Input and output.** Input: the raw ZIP bytes. Output: the `CUSTOM_OFFICE_*` rules (one MEDIUM:
   macro declaration mismatch; several LOW and INFO). If an essential part cannot be read, the
   result is `CustomScanError`, and so UNABLE_TO_SCAN.
4. **Functions:**
   - `ooxml_package.open_package`, `_content_types`, `_relationships`, `resolve`, `main_document`;
   - `ooxml.declaration` (C4), `reachable` and `relationships` (C5), `_local_header` and
     `container` (C6), `analyse`.
5. **Data structures.** Relationships are kept as a map from source part to its relationships,
   with targets resolved to part keys (OPC §9.3). Reachability is a BFS from the package root.
6. **Original or reused.** The OPC reader and all three methods are original. Reused: `zipfile`,
   for the central directory and member reads, and defusedxml, which rejects DTDs and entities.
7. **References.** ECMA-376 Part 2 (OPC: content types, relationships, §9.3 part-name resolution);
   PKWARE APPNOTE (ZIP local and central headers).
8. **Complexity and limits.**
   - at most 5,000 entries and 100,000 relationships;
   - XML parts of at most 16 MiB, other parts of at most 32 MiB, and 64 MiB read per document;
   - the BFS is O(parts + relationships).
9. **False-positive risks.** Leftover parts and high compression are common in benign files, so
   they are INFO. LOW is used only for structures standard generators do not produce.
10. **Limitations.** Non-Office OPC packages (XPS, Visio, ...) get only the container checks, and a
    coverage finding says so. The content of parts is not judged here: §8, §9 and the Office
    scanner do that.
11. **Tests and results.** `tests/test_custom_ooxml.py` (80 tests). Case 7 gives
    `CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH MEDIUM`.
12. **What to tell Dr. Haque.** "Office never trusts the file extension; it follows the package's
    content-type declarations and relationship graph. We read the package the same way and report
    where the declarations and the actual bytes disagree. The best example is a document that
    declares itself macro-free but carries a macro project."

**Inert example** (case 7). A `.docx` main type with a placeholder `word/vbaProject.bin` and a
`vbaProject` relationship gives `CUSTOM_OFFICE_MACRO_DECLARATION_MISMATCH MEDIUM: The package is
declared as a macro-free Word document but contains macro code ... macro part
'word/vbaProject.bin'; relationship 'rId3' of type vbaProject in 'word/_rels/document.xml.rels'.`

---

## 6. PDF action chains and attachment verification (`pdf-chains`; `pdf_chains.py`, `pdf_attachments.py`, `c2pa.py`)

1. **Threat.** A PDF that runs code when opened and uses it to launch or export an embedded file
   (a dropper). The old rule combined "an automatic script anywhere" with "an attachment
   anywhere". That flagged harmless PDFs whose attachment has nothing to do with the script.
2. **Algorithm.**
   - **Chains.** A chain is one trigger (`/OpenAction`, `/AA` with an automatic key, `/A` on a
     click, a document-level script) plus its action dictionary and its `/Next` list, nothing
     more. A payload link is created by:
     - `Launch /F` naming an embedded file;
     - `GoToE`;
     - a JavaScript `exportDataObject` with a literal `cName`. A computed name links to every
       attachment.

     An escalation needs the automatic trigger *and* the payload on the same chain.
   - **Attachments.** Every object in the cross-reference table is visited. Every raw
     `/EmbeddedFile` token, and every `N G obj` header, must be explained by that table.
   - **Verification.** Each embedded stream is decoded (bounded) and verified as code-free from its
     *bytes* as one of two things:
     - an OpenDocument package with no code: the LibreOffice "hybrid PDF";
     - a C2PA manifest store with no active content, verified by a full JUMBF, CBOR, JSON, SVG,
       JPEG and PNG structure walk.

     Anything else is "not verified".
3. **Input and output.** Input: the PDF bytes, parsed with pypdf under the PDF scanner's limits.
   Output:
   - `ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT` / `_LAUNCH` (HIGH);
   - `_OPENS_EMBEDDED_DOCUMENT` / `_SCRIPT` (MEDIUM);
   - `ENGINE_PDF_USER_TRIGGERED_SCRIPT` (INFO);
   - `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` (LOW);
   - `ENGINE_PDF_CHAINS_REPAIRED` (INFO).
4. **Functions:**
   - `pdf_chains`: `_describe`, `_actions`, `_name_tree`, `extract`, `scan`;
   - `pdf_attachments`: `inspect`, `inspect_stream`, `odf_without_code`, `_empty_tree`;
   - `c2pa`: `verify`, `boxes`, `_Store`, `jpeg_problem`, `png_problem`;
   - findings: `correlate.chain_findings`, `attachment_findings`.
5. **Data structures.**
   - `Chain(trigger, actions)` and `Action(kind, payload links)`.
   - A walk of the object graph with a seen-set.
   - Shared budget counters (`spent`) across all attachments of one PDF.
   - The C2PA verifier is a recursive box parser with explicit depth limits.
6. **Original or reused.** The chain model, the same-chain escalation rule, the table-versus-raw
   accounting, and the ODF and C2PA verifiers are original. pypdf provides object parsing and
   stream decoding.
7. **References.** ISO 32000-1 §12.6 (actions, triggers, `/Next`) and §7.11.4 (embedded files).
   Adobe JavaScript for Acrobat API Reference (`exportDataObject`). C2PA 2.2 Annex A.4;
   ISO/IEC 19566-5 (JUMBF); RFC 8949 (CBOR); ODF 1.3 Part 2 (package).
8. **Complexity and limits.**
   - at most 200,000 objects, depth 64, and 10,000 actions;
   - at most 100 attachment streams, 64 MiB decoded;
   - for ODF: at most 100 members, 4 MiB per member, 16 MiB per package;
   - fixed per-PDF C2PA limits (boxes, items, text, SVG elements, JPEG/PNG parts).

   Exceeding a limit raises, and the result is UNABLE_TO_SCAN. Nothing is silently cut off.
9. **False-positive risks.** A PDF whose opening script exports its own attachment on purpose (a
   form that saves data) is HIGH. That is deliberate: a document that delivers an embedded file
   automatically is exactly the dropper pattern.
10. **Limitations.**
    - Embedded documents opened by GoToE are not analysed recursively.
    - C2PA signatures and claims are not checked; "verified" means "no active content", not
      "authentic".
    - A structure that pypdf had to repair disables the replacement of the PDF scanner's findings
      (fail closed).
11. **Tests and results.** `tests/test_pdf_chains.py` (18 tests), `tests/test_c2pa_manifests.py`
    (116 tests), and the attachment tests in `tests/test_pdf.py`. Cases 5a and 5b differ exactly as
    intended (below).
12. **What to tell Dr. Haque.** "We model which trigger runs which actions, following the
    standard's action and `/Next` structure. We escalate to MALICIOUS only when an automatic chain
    itself delivers an embedded file. An unrelated attachment next to a script is reported, but
    not treated as one attack. Attachments are judged by parsing their bytes, never by the name or
    MIME type the author chose."

**Inert example** (cases 5a and 5b; same script trigger, one text attachment):

- **5a**: the `/OpenAction` JavaScript never names the attachment. Result:
  `ENGINE_PDF_AUTO_CHAIN_SCRIPT MEDIUM: An automatic action chain runs JavaScript; no embedded file
  is used on that chain.` and `ENGINE_PDF_ATTACHMENTS_UNVERIFIED LOW` (`notes.txt`: not an
  OpenDocument package). Verdict: **SUSPICIOUS**.
- **5b**: the script calls `exportDataObject({cName: "f", nLaunch: 0})`. Result:
  `ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT HIGH: ... catalog /OpenAction: JavaScript (object 7 0)
  (exports 'f')`. Verdict: **MALICIOUS**.

---

## 7. PDF content-stream integrity (`pdf-integrity`; `app/engine/pdf_integrity.py`)

1. **Threat.** Page content streams that cannot be decoded. Content no reader could read was not
   inspected, so SAFE would be unjustified.
2. **Algorithm.** Resolve every page's `/Contents` and decode it through an allow-list of byte
   filters (`SUPPORTED_FILTERS`): FlateDecode, LZWDecode, ASCIIHexDecode, ASCII85Decode and
   RunLengthDecode, plus their abbreviations. Anything outside the list, or any decode failure, is a
   coverage gap, not a pass. Why: it turns "we could not read it" into an explicit reason instead
   of silence.
3. **Input and output.** Input: the PDF. Output: coverage findings, or an error. An error gives
   UNABLE_TO_SCAN, whose reason determines whether an override is allowed.
4. **Functions:** `PdfIntegrityScanner.scan`, `_filters`, `_resolve`.
5. **Data structures.** A filter allow-list, a counter of decoded bytes, a stream count.
6. **Original or reused.** The coverage accounting is original. pypdf decodes.
7. **References.** ISO 32000-1 §7.4 (filters) and §7.8 (content streams).
8. **Complexity and limits.** At most 10,000 content streams, 32 MiB decoded in total; linear in
   the decoded bytes.
9. **False-positive risks.** None in the sense of reporting something as malicious. It can turn a
   damaged but harmless PDF into UNABLE_TO_SCAN.
10. **Limitations.** A PDF that pypdf cannot open at all is classified as an internal error
    (SCANNER_INTERNAL_ERROR, deny), not as a malformed document. This is documented and deferred
    (`docs/security-integration-v1-readiness.md`). It fails closed.
11. **Tests and results.** `tests/test_pdf_integrity.py` (12 tests).
12. **What to tell Dr. Haque.** "SAFE requires complete inspection. This scanner proves the page
    content was actually decodable; if it was not, the user sees *why* the file could not be fully
    checked."

---

## 8. OOXML activation graph (`ooxml-links`; `app/engine/ooxml_links.py`)

1. **Threat.** External resources that a document fetches by itself: a remote template (the
   classic template-injection technique), linked OLE objects that update automatically, and remote
   pictures. Also embedded objects and ActiveX controls.
2. **Algorithm.**
   - Compute which parts Office actually loads: a BFS over relationship types Office follows from
     the main document.
   - In each loaded part, find the element that references each relationship Id (`r:*`
     attributes, VML `o:relid`).
   - Classify by that element's documented semantics: `on-open`, `linked-picture`, `on-action`,
     `click`, `displayed`, `not-activated` or `undetermined`.

   Why: a relationship that no loaded element references is never used. Listing every external
   relationship (as the Office scanner does) overstates the risk. The element decides *when* the
   target is used.
3. **Input and output.** Input: the OOXML package (from the C4–C6 reader). Output:
   - `ENGINE_OFFICE_EXTERNAL_ON_OPEN` (MEDIUM);
   - linked-picture and on-action findings;
   - `ENGINE_OFFICE_EMBEDDED_OBJECT_NOT_DISPLAYED` (INFO);
   - `ENGINE_OFFICE_LOCAL_FILE_TARGETS`;
   - plus "accounts for" lines, which let correlation replace a coarser Office-scanner finding.
4. **Functions:** `loaded_parts`, `_chain`, `references`, `reference_targets`, `classify`,
   `analyse`, `_read_references`, `scan`. The findings are built in `correlate.link_findings`.
5. **Data structures.** A graph of parts and relationships, a BFS parent map (to print the chain
   `package -> document.xml -> settings.xml -> attachedTemplate`), and a map from Id to the
   referencing elements.
6. **Original or reused.** The loaded-part model, the Id-to-element resolution and the activation
   classes are original. The OPC reader is §5's, also ours. defusedxml parses XML.
7. **References.** ISO/IEC 29500-1 element semantics (`w:attachedTemplate`, `a:blip r:link`,
   `o:OLEObject Type="Link"`/`UpdateMode`, `oleUpdate`, `p:link updateAutomatic`); the Microsoft
   Learn Open XML reference; MITRE ATT&CK T1221 (template injection).
8. **Complexity and limits.** O(parts + relationships) for the BFS, plus one XML parse per loaded
   part, under §5's limits.
9. **False-positive risks.** Corporate templates on a file share are common. Local file targets are
   reported at INFO, and `on-open` is MEDIUM, never HIGH.
10. **Limitations.** It models documented element semantics, not observed Office behaviour.
    Elements it does not model are `undetermined`. Whether Office actually fetches the resource
    also depends on Protected View and policy.
11. **Tests and results.** `tests/test_ooxml_links.py` (53 tests). Cases 6a–6g: the hyperlink
    produces nothing; the template referenced from settings is `on-open` MEDIUM; the embedded
    object with no element is INFO.
12. **What to tell Dr. Haque.** "Many scanners list every external URL in a document. We compute
    which ones Office would use, and when: on open, when displaying a picture, or only when the
    user clicks. We follow the same path Office follows, from the package root through each part
    it loads to the element that uses the relationship."

**Inert example** (case 6c). The result is `ENGINE_OFFICE_EXTERNAL_ON_OPEN MEDIUM: ... Evidence:
package -> word/document.xml (officedocument) -> word/settings.xml (settings) -> attachedTemplate
id='rId1' -> attachedtemplate https://template.example.invalid/normal.dotm (w:attachedTemplate: the
template is attached when the document opens)`. The `.invalid` domain can never resolve.

---

## 9. C7: Word field codes (`word-fields`; `app/engine/word_fields.py`)

1. **Threat.** DDE and DDEAUTO fields that start a program, and INCLUDETEXT and INCLUDEPICTURE
   fields that fetch remote content. They are often split across runs, or built with a nested
   QUOTE field, to hide from keyword scanners.
2. **Algorithm.**
   - Rebuild each field's instruction from simple fields (`w:fldSimple`) and from complex fields
     (`fldChar` begin, separate, end, with `instrText` split across runs). A stack of open fields
     handles nesting.
   - Replace each nested field by `NESTED`.
   - Separate live text from tracked deletions (`w:delInstrText`).
   - Tokenize the instruction as Word does (quotes, `\\` escapes, switches) and classify it by the
     field type and its target. A program path, an executable or a command interpreter is treated
     as a program.

   Why: the instruction exists only after the runs are reassembled. Deleted text is evidence, but
   not what Word evaluates.
3. **Input and output.** Input: the XML of every part Office loads (via `ooxml_links.loaded_parts`).
   Output:
   - `ENGINE_WORD_DDEAUTO_PROGRAM` (HIGH);
   - `ENGINE_WORD_DDE_PROGRAM` (MEDIUM);
   - `ENGINE_WORD_DDE_APPLICATION` (LOW);
   - `ENGINE_WORD_REMOTE_INCLUDE` (MEDIUM) and the picture variant;
   - `ENGINE_WORD_DELETED_INSTRUCTION` (INFO).
4. **Functions:** `fields`, `tokens`, `is_program`, `target_class`, `classify`, `scan`, `findings`,
   `FieldScanner`.
5. **Data structures.** A stack of open fields (`_Open`), and a `Field(part, live text, deleted
   text, nested)` record.
6. **Original or reused.** The field reconstruction, the tracked-change semantics and the
   classification are original. defusedxml parses.
7. **References.** ECMA-376 Part 1 §17.16 (fields, the field-instruction syntax of §17.16.1) and
   §17.13.5 (revisions); Microsoft ADV170021 (DDE hardening).
8. **Complexity and limits.** One linear pass over each part's XML events; part sizes are bounded
   by §5's limits.
9. **False-positive risks.** DDE to Excel by server name is a legitimate data link, so it is LOW.
   HIGH requires DDEAUTO and a program.
10. **Limitations.**
    - Nested fields are never evaluated: a QUOTE-built command is "built by a nested field", which
      is itself treated as a program.
    - Only WordprocessingML is covered. Excel DDE formulas are not part of this detector.
11. **Tests and results.** `tests/test_word_fields.py` (69 tests).
12. **What to tell Dr. Haque.** "Word stores a field's instruction in pieces, which can be split
    across runs, nested, or partly deleted in tracked changes. We reassemble it as Word does,
    classify the live instruction, and report deleted instructions separately, because they only
    come back if a reviewer rejects the change."

**Inert example.** `DDEAUTO c:\\windows\\system32\\cmd.exe "/c calc"` in `word/document.xml` (never
evaluated). Result: `ENGINE_WORD_DDEAUTO_PROGRAM HIGH: A DDEAUTO field, updated when the document
opens, names a program or command interpreter as its application ... Evidence: word/document.xml:
DDEAUTO c:\\windows\\system32\\cmd.exe "/c calc"`.

---

## 10. Correlation (`app/engine/correlate.py`)

1. **Threat addressed.** Two problems from running several scanners:
   - double counting the same evidence;
   - coarse findings that a more precise analysis has disproved, or confirmed.
2. **Algorithm.** A finding is removed or qualified only when a stated precondition holds; if it
   does not, the finding stands. Every change is recorded as a "raw scanner:rule SEVERITY:
   description" line in the `ENGINE_CORRELATION` evidence, so nothing disappears without a trace.
   The rules:
   - The PDF scanner's `PDF_AUTO_JAVASCRIPT*` findings are replaced by the chain rules, only if
     both scanners completed on an unrepaired structure.
   - The JavaScript signature is merged into a confirming automatic-script chain (Phase 4).
     Otherwise it is kept and marked "not confirmed".
   - `OFFICE_MACRO_AUTOEXEC_EXECUTION` is **never removed**; vba-chains only adds a path or a
     qualification.
   - An "accounts for" finding may replace a coarser one only when both scanners completed. A
     higher severity may be replaced only by the four validated rules in `SUPERSEDING`, and only
     up to the validated level.
3. **Input and output.** Input: the `WorkerReport`. Output: the same report with adjusted findings
   and the `ENGINE_CORRELATION` audit evidence.
4. **Functions:** `correlate`, `accounted`, and the chain, VBA and link finding builders.
5. **Data structures.** Findings keyed by (scanner, rule_id), plus the per-scanner completion
   status.
6. **Original or reused.** Fully original.
7. **References.** The project's benign-corpus validation (`docs/evidence/benign-corpus`), which
   documents why each superseding rule is allowed.
8. **Complexity.** O(findings).
9. **False-positive risks.** It *reduces* false positives, so its risk is the opposite: removing a
   true positive. Hence the fail-closed preconditions and the audit lines.
10. **Limitations.** The replacement rules are hand-written and validated on the corpora; a new
    scanner needs its own explicit rules.
11. **Tests and results.** `tests/test_correlate.py` (19 tests), including the Phase 4 merge, which
    is kept when the chains failed, were repaired or found no chain.
12. **What to tell Dr. Haque.** "Several analyses look at the same file. Correlation merges
    duplicates and lets the more precise analysis replace the coarse one, but only when that
    analysis completed. Every change is written into the evidence, so an auditor can see what was
    merged and why."

---

## 11. Structural scanners kept from before (`office`, `pdf`)

These are earlier work and were kept; they are summarised here for completeness.

- **`office`** (`app/scanners/office.py`) covers OLE and OOXML structure:
  - ZIP limits, path traversal and duplicate names;
  - external relationship classes;
  - the Equation Editor CLSID (CVE-2017-11882 family);
  - an executable extension in an `Ole10Native` header;
  - DDE fields;
  - encryption.

  Its macro part now uses §2. olefile, msoffcrypto (the header only) and `OleNativeStream` parse.
- **`pdf`** (`app/scanners/pdf.py`) walks the pypdf object graph from the catalog: JavaScript,
  automatic triggers, `/Launch`, attachments and coverage. It also defines the decompression
  limits that `pdf-chains` and `pdf-integrity` share.

---

## Milestones: walkthroughs and self-test questions

Answers are in the collapsed blocks. Try each question before opening its answer.

### Milestone 1: audit and baseline (commit ee27b6f)

**Walkthrough.**

- Tagged the starting point (`b6774be`, `baseline/pre-custom-rebuild`).
- Ran the full suite: 1203 passed, 43 skipped.
- Captured the detection evidence (case matrix, both benign corpora) before any change.
- Classified every module as custom, third-party detection, permissible parser, infrastructure or
  redundant.

The audit found three third-party *decision* points:

- YARA-X matching;
- olevba's `analyze_macros` classifications in the Office scanner;
- olevba's keyword tables inside `vba_chains`.

It also found that the reference engine's JavaScript rule was computed and then discarded on every
scan. See [architecture-audit.md](architecture-audit.md).

1. Why was the baseline evidence captured *before* the first code change, and what would be lost
   by capturing it afterwards?
2. olevba's `VBA_Parser.extract_macros` was kept but `analyze_macros` was not. What is the
   principled difference?
3. Why does a change to the scanner roster require a coordinated Conversion Engine release?

<details><summary>Answers</summary>

1. The comparison in Phase 6 needs outcomes from code that the rebuild had not touched. Evidence
   captured later could already contain the change being measured, and regressions would be
   invisible.
2. `extract_macros` is *parsing*: it decompresses MS-OVBA and walks OLE streams, a deterministic
   format transformation with no opinion. `analyze_macros` is *detection*: its keyword tables
   decide what is suspicious. The dependency policy allows the first and forbids the second.
3. The Conversion Engine verifies the signed receipt's exact roster (`ROSTER`,
   `filesmagic-engine/app/security_gate.py`). A different roster gives `RECEIPT_WRONG_ROSTER`, and
   conversions are refused. That refusal is deliberate: it prevents an unvalidated engine build
   from approving files.
</details>

### Milestone 2: custom signature matcher (commit 3ac9e69)

**Walkthrough.**

- Wrote `signatures.py` with the YARA semantics our rules need: start-offset matches, overlap,
  `nocase`, `wide`, ranges, saturating counts, and the regex window.
- Ported the nine non-redundant rules as Python data.
- Replaced `yara-x` and `yara-x-engine` with one `signatures` scanner.
- Proved equivalence differentially against YARA-X on more than 5,000 inputs.

1. Why does the matcher restart its search one byte after the previous match's *start*, not its
   end? Give an input where the two choices count differently.
2. What does "the count saturates at 1000" mean for a rule that compares two counts, and how do
   the rules handle it?
3. Why is a differential test against YARA-X stronger evidence than unit tests written from the
   YARA documentation?

<details><summary>Answers</summary>

1. YARA counts every start offset, and matches may overlap. In `aaa`, the pattern `aa` matches at
   offsets 0 and 1. Restarting after the end (offset 2) finds only one, so a `#x > 1` condition
   would differ.
2. After 1000 matches the count is a lower bound, not exact. The refined JavaScript rule counts
   every `/OpenAction` and `/AA` and discounts only those that the bytes *prove* are user-triggered.
   If either count reaches the cap, nothing is discounted (`#open >= 1000 or #aa >= 1000` in the
   condition), so the rule fires wherever the generic rule would. That is the conservative branch.
3. Unit tests encode *our reading* of the documentation; if that reading is wrong, test and code
   are wrong together. The oracle is the real implementation. The corpus includes fuzzed inputs at
   the boundaries (offset 1024 versus 1025, the 4,095-byte window), where misreadings show up.
</details>

### Milestone 3: custom VBA analysis (commit 5b31ef1)

**Walkthrough.**

- Wrote `vba_analysis.py`: tokenizer, entry-point table, capabilities resolved on their receiver,
  and bounded constant folding.
- Rewired the Office scanner and `vba_chains` to it; olevba is now only an extractor.
- Built real, inert MS-OVBA projects (`tests/vba_fixtures.py`: compressed source, no P-code) so
  the whole path, including the isolated worker, is tested.
- Fixed a baseline bug on the way: module names kept their `.bas` extension, so qualified calls
  never resolved.

1. Why is `o.Run "x"` DEMONSTRATED execution in case v09 but only POSSIBLE in case v14?
2. When does a folded string count as obfuscation, and why does that rule avoid flagging an
   ordinary `"Hello " & name`?
3. Why must the `Replace` fold check the result's size *before* building it?

<details><summary>Answers</summary>

1. In v09 the receiver `o` was assigned `CreateObject(<fold = "WScript.Shell">)`, so its type is
   known, and `Run` on WScript.Shell starts a program. In v14 nothing tells the analysis what
   `obj` is, so it reports "could be execution" (POSSIBLE). It neither ignores it nor claims it.
2. When the folded value contains a sensitive token (an interpreter, ProgID, API, URL or Run key)
   that none of its source literals contains on its own. `"Hello " & name` does not fold at all
   (`name` is a variable), and if it did, nothing sensitive would appear.
3. `Replace` can multiply the length: `Replace(String(60000,"a"),"a",String(60000,"b"))` would
   build a 3.6-billion-character string before any later check. The fold first computes the upper
   bound `len(s) + count(old in s) · len(new)` and refuses when it exceeds `MAX_FOLDED`
   (`vba_analysis.py:497`). That keeps memory bounded, which is a denial-of-service defence inside
   the worker.
</details>

### Milestone 4: PDF and Office consolidation (commit ea9ce89)

**Walkthrough.**

- Removed the remaining duplicate result: when the chain analysis confirms an automatic script, the
  JavaScript signature is merged into that chain finding ("counted once").
- Kept the signature when the chains failed, saw a repaired structure, or found no chain.
- Verified that an unrelated attachment next to a script (5a) is not one chain, and that an export
  (5b) is.
- Deliberately kept some overlaps, because they are independent evidence: `PDF_JAVASCRIPT` next to
  the chain, and `OOXML_VBA_Macros` next to `OFFICE_MACROS_PRESENT`.

1. Why is the signature kept, not merged, when pypdf had to repair the structure?
2. Cases 5a and 5b contain the same script trigger and the same attachment. What exactly makes 5b
   MALICIOUS?
3. Why keep `OOXML_VBA_Macros` (signatures) *and* `OFFICE_MACROS_PRESENT` (office) instead of
   deduplicating them?

<details><summary>Answers</summary>

1. A repaired structure means the parser's view of the file may differ from the bytes, which is
   exactly where a raw signature can see something the parser missed. Merging requires
   independent confirmation; a repaired parse is not reliable confirmation.
2. In 5b the script on the `/OpenAction` chain calls `exportDataObject` with `cName "f"`, which
   names the attachment, so the payload is linked on the same chain. In 5a the attachment exists,
   but no action on the automatic chain uses it.
3. They are independent methods. If olefile or the extractor fails on a malformed project, the
   byte signature still fires. Losing one signal on hostile input must not mean losing detection.
</details>

### Milestone 5: unified architecture cleanup (commit 2308739)

**Walkthrough.**

- `engine=unified` is the only engine. `engine=reference` is refused with **410 ENGINE_RETIRED**,
  before authentication is checked, and never answered by another engine.
- yara-x was removed from the runtime requirements (kept only as a development oracle), along with
  its scanner, its rule files and the research flags.
- The worker always runs the unified roster, then `correlate()`.
- A test runs the service in a subprocess and proves `yara_x` is never imported. An AST check
  proves olevba's heuristics are never called.

1. Why return 410 for `engine=reference` instead of silently running the unified engine?
2. Why check `sys.modules` in a *subprocess* instead of in the test process?
3. The receipt's `ruleset_sha256` changed meaning in this phase. Does the Conversion Engine depend
   on it, and how did you find out?

<details><summary>Answers</summary>

1. A client that asks for an engine must get that engine or an explicit error. A silent
   substitution would make receipts claim a different analysis than the caller requested, which is
   exactly what the spec forbids ("the API must not silently select a retired engine").
2. The test process imports yara_x itself, for the parity tests. Only a fresh interpreter that
   imports the service and scans shows what the *service* loads.
3. It does not. `security_gate.py` verifies the engine, the commit, the roster, the authorization
   and the verdict claims, but not the ruleset hash or the scanner versions; reading
   `verify_receipt` in read-only mode showed this. So only `ROSTER` and `SECURITY_ENGINE_COMMIT`
   must change there.
</details>

### Milestone 6: full regression (commit dd94694)

**Walkthrough.**

- Re-ran the case matrix and both benign corpora, and compared them with the baseline: 0 verdict
  changes, 0 benign changes, 3 intended merges.
- Built a 16-case VBA matrix and ran it through *both* trees' real workers: 5 baseline false
  positives removed, 4 new HIGH chains found.
- Measured the matcher against YARA-X, plus determinism and latency.
- Recorded the limits of the evidence honestly: synthetic only, no VBA in the benign corpora,
  worker memory not measured on Windows.

1. Five VBA cases went from MALICIOUS to SUSPICIOUS. What changes for a user, and why is that
   acceptable for each?
2. YARA-X matching is about 6× faster than our matcher, but our matcher is faster per file in the
   service. Explain.
3. Why can the regression *not* support a claim about real-world detection accuracy?

<details><summary>Answers</summary>

1. MALICIOUS blocks conversion; SUSPICIOUS converts only with explicit consent. Each of these cases
   has no demonstrated execution:
   - `vbHide` is a constant;
   - `Application.Run` starts a macro;
   - `SHGetFolderPathA` reads a path;
   - `Shell` is the user's own procedure;
   - the object behind `Run` is unknown.

   The file is still flagged, and the findings say why.
2. The retired scanner built a new `yara_x.Scanner` for every file, and that setup dominated:
   1,472 ms for the corpus, against 8.5 ms with one reused scanner. Ours has no per-file setup
   (48.8 ms).
3. All inputs are synthetic or benign. They show that each behaviour changed as designed, not how
   often real malware uses these techniques, or evades them. That needs approved samples in the
   isolated VM (`docs/malware-sample-handling-procedure.md`).
</details>

### Milestone 7: documentation and integration readiness

**Walkthrough.** This guide, the regression report, and the integration plan. No change was made
to the Conversion Engine or the frontend; they were inspected read-only.

1. Which single Conversion Engine change is *required* for integration, and what happens if it is
   forgotten?
2. Which frontend behaviour breaks now that `reference` is retired, and is that a security
   problem?
3. Name two limitations a reviewer could use to bypass the VBA detector, and say what the engine
   does in each case.

<details><summary>Answers</summary>

1. Update `ROSTER` to the nine new names, together with `SECURITY_ENGINE_COMMIT`. If it is
   forgotten, every receipt fails with `RECEIPT_WRONG_ROSTER`, and every conversion is refused:
   fail closed, but a complete outage.
2. The Security Engine Lab UI (`Security Engine/frontend`) still offers "Original Engine", and
   falls back to it if `/health` fails; that request now returns 410. It is a usability problem,
   not a security one: the API refuses explicitly. The product frontend is unaffected, because it
   talks only to the Conversion Engine.
3. Two examples:
   - **VBA stomping** (malicious P-code, benign source): the source shows nothing, but "macros
     present" still keeps the file SUSPICIOUS at worst, and "no-path" never lowers a finding.
   - **An object passed as a parameter, or from `GetObject` with a computed name**: the call is
     POSSIBLE, so the file is SUSPICIOUS, not MALICIOUS.

   In neither case is the file SAFE.
</details>

---

## What to study before presenting

1. The verdict and authorization rules in `app/decision/__init__.py`: why SAFE needs complete
   inspection, and which UNABLE_TO_SCAN reasons allow consent.
2. One full trace per format, using the inert examples above:
   - PDF case 5b: lexer → chains → correlate → decision;
   - VBA case v09: extraction → tokens → fold → receiver → entry → graph;
   - OOXML case 6c: package → loaded parts → element → activation.
3. The differential-testing argument for the signature matcher, and the honest performance result.
4. Each detector's limitations (item 10). They are the questions a reviewer will ask first:
   P-code, XLM, flow-insensitivity, recursion into GoToE, and the pdf-integrity classification.
5. The regression report's §2 table: be able to justify each changed verdict in one sentence.
