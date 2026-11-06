# Custom Security Engine: research log (Nov 6, 2026 onward)

Follows [custom-engine-approved-plan-2026-11-06.md](custom-engine-approved-plan-2026-11-06.md).
Branch `feature/custom-unified-engine-nov18`, based on `security/malware-research-hardening` (`c8bf8dd`).

Status labels used below: **implemented** (in the code, unit-tested), **measured** (numbers from a
recorded run in `docs/evidence/`), **proposed** (not built), **rejected** (measured and dropped).

## 1. Status at a glance

| Item | Status |
|---|---|
| Case matrix harness `evaluation/cases.py` (10 inert cases, real isolated worker) | implemented (`1d6db56`) |
| Baseline: test suite, detection matrix, latency, start-up profile | measured (sections 5-6) |
| Module 1: PDF action-chain extraction `app/engine/pdf_chains.py` | implemented (`d8b3bec`) |
| Module 2: chain findings + evidence correlation `app/engine/correlate.py`, `--engine=unified` | implemented (`51a5049`) |
| Reference vs unified comparison on the 10 cases | measured (section 8) |
| Correction 1: click-only scripts behind a page destination (explicit classification + regressions) | implemented (`7dc8fe8`), measured (section 12) |
| Correction 2: refined bytes-only YARA-X rule for automatic triggers `app/engine/rules/pdf.yar` | implemented (`7dc8fe8`), measured (section 12) |
| Linux-only isolation tests (28) | passed in CI on GitHub's Ubuntu 24.04 runner at `2721a25` (section 15); not run on Render or the VM |
| Office: VBA call-graph analysis `app/engine/vba_chains.py` | implemented (`7d9f69c`), unit-tested on inert source strings (section 14) |
| Format-aware worker start-up (latency) | proposed, needs a security decision (section 10) |
| YARA-X compiled-rule reuse; YARA-X `fast_scan` | rejected by measurement (section 6) |
| Office: external relationships and embedded objects on the package graph | proposed, next |

## 2. Environment and reproduction

- Windows 11 Pro 10.0.26300, Python 3.14.3, the repository's `.venv`. A **development**
  environment: the worker runs, but Linux-only isolation (namespaces, capabilities, rlimits) is
  absent, so `isolation_missing` is non-empty in every result. Research-grade numbers must be
  re-run on the Linux evaluation VM; numbers are compared only within one environment.
- Pinned versions (installed metadata): yara-x 1.21.0, pypdf 6.19.0, oletools 0.60.2, olefile 0.47,
  defusedxml 0.7.1, msoffcrypto-tool 6.0.0, pcodedmp 1.2.6, pytest 9.1.1.
- `working_tree_dirty: true` in every run: only the student's uncommitted EICAR/Didier study
  documents under `docs/` (not code) were modified at the time.

```
python -m pytest -q -p no:cacheprovider --basetemp <writable dir>      # see note below
python -m evaluation.cases --trials 20 --out <dir>                     # reference engine
python -m evaluation.cases --trials 20 --engine unified --out <dir>    # custom engine candidate
```
Note: on this machine pytest's default temporary directory is not writable from the sandboxed
shell (58 tests error with `PermissionError` in `tmp_path`); `--basetemp` fixes that. It is an
environment issue, not a test failure.

## 3. Reused components, licenses and attribution

Every component is used as an installed library. **No upstream source code is copied** into this
repository; if that changes, the fragment, its origin and its license are recorded here first.

| Component | Version | License | What we use | Why reuse instead of writing it |
|---|---|---|---|---|
| YARA-X (VirusTotal) | 1.21.0 | BSD-3-Clause | `Compiler`, `Rules`, `Scanner` (timeout, match cap) via the existing `app/scanners/yarax.py` | A correct, fast, sandboxed pattern matcher is a multi-year Rust project; our contribution is the rules and how matches are interpreted |
| pypdf | 6.19.0 | BSD-3-Clause | `PdfReader`, generic objects, `apply_configuration` decompression limits, `DictionaryObject.raw_get` | PDF parsing (xref repair, object streams, filters, encryption) is large and security-critical; pypdf has documented output limits |
| oletools (Philippe Lagadec) | 0.60.2 | BSD-2-Clause (package); `thirdparty/` has its own licenses (oledump extract by Didier Stevens, prettytable, xglob, xxxswf) | `olevba.VBA_Parser`, `oleobj.OleNativeStream` via `app/scanners/office.py` | VBA decompression (MS-OVBA) and keyword analysis are mature and well-documented |
| pcodedmp | 1.2.6 | **GPL-3.0** | Not imported by us; `olevba` imports it lazily for P-code disassembly | Transitive dependency of oletools. Fine for local research; **must be disclosed**, and GPL obligations apply if the Docker image is ever distributed |
| olefile | 0.47 | BSD-2-Clause | OLE2 container reading in the Office scanner | Same reason as oletools |
| defusedxml | 0.7.1 | PSF-2.0 | XML parsing with DTDs/entities rejected | Hardened XML parsing is a known pitfall (XXE, billion laughs) |
| msoffcrypto-tool | 6.0.0 | MIT | Encryption detection in the Office scanner | Encryption formats (MS-OFFCRYPTO) |

Poster attribution: "Built on YARA-X (VirusTotal, BSD-3), pypdf (BSD-3) and oletools (P. Lagadec,
BSD-2; includes GPL-3 pcodedmp as a dependency)." Original contributions are listed in section 7.

Sources used for the new code (all verified against the **installed** source of the pinned versions):
- pypdf 6.19.0 `pypdf/generic/_data_structures.py`: `DictionaryObject.__getitem__` resolves indirect
  objects (line 492-493); `raw_get` returns the stored value unresolved (line 439-440).
- ISO 32000-1:2008: 12.6.2 action dictionaries and `/Next` sequences; 12.6.3 trigger events
  (`/OpenAction`, `/AA` tables for annotations, pages, form fields and the catalog); 12.6.4.4 GoToE
  (`/T` target dictionary, `/N` embedded-file name); 12.6.4.5 Launch (`/F`, `/Win`); 12.6.4.13
  Rendition (`/JS`); 7.9.6 name trees; 7.11.4 embedded file streams (`/EF`).
- Adobe Acrobat JavaScript API reference, `Doc.exportDataObject` (`cName`, `nLaunch` 0/1/2) and
  related data-object methods. Not re-fetched in this session; the engine depends only on the
  method names and the `cName` argument.
- Existing project code reused, not duplicated: `app/scanners/pdf.py` (`PDF_LIMITS`, `SKIP_KEYS`,
  `AUTO_TRIGGERS`, `text_of`, `filespec_name`, `_RepairLog`), `app/scanners/custom/indicators.py`
  (`clean`, `listing`, `NOT_PROOF`), `app/decision` (`decide`), `app/worker.py` (`analyse`, `run`).

## 4. Existing detectors (reviewed so the engine does not duplicate them)

- **YARA-X rules** (`app/rules/filesmagic.yar`): byte co-occurrence only. Blind to `#xx` name
  escapes and compressed streams (stated in the rule file itself).
- **PDF scanner** (`app/scanners/pdf.py`, pypdf): graph walk from the catalog; JS, Launch, URI
  schemes, attachments, forms. "Automatic" is one boolean passed down to everything reachable
  from an automatic trigger.
- **Office scanner** (`app/scanners/office.py`, oletools): VBA (autoexec + strong behaviour = HIGH),
  OLE objects, ZIP abuse, external relationships, DDE.
- **Custom C1** (`app/scanners/custom/pdf.py`): own lexer; PDF names written with unnecessary
  `#xx` escapes, including inside FlateDecode object streams.
- **Custom C4-C6** (`app/scanners/custom/ooxml.py`): OOXML declaration consistency, relationship
  graph, ZIP container metadata.
- **Verdict** (`app/decision`): any HIGH/CRITICAL → MALICIOUS; LOW/MEDIUM → SUSPICIOUS; no scanner
  ran or one failed → UNABLE_TO_SCAN; else SAFE. Evidence wins over failure.

## 5. Case matrix (all inert, all ground truth BENIGN)

Built in memory by `evaluation.cases.cases()` from the repository's fixture builders; the same
bytes are used by the unit tests. An "indicator" is an inert structure, not malware.

| Case | Plan scenario | Indicator |
|---|---|---|
| 1-pdf-clean | 1 | none (negative control) |
| 2-pdf-form-keystroke-js | 2 | form-field keystroke JavaScript (`/AA /K`, user-triggered) |
| 2b-pdf-open-at-page-click-js | 2 | `/OpenAction [page /Fit]` + a click-only link script |
| 3-pdf-escaped-openaction-js | 3 | `/OpenAction` script written `/J#61vaScript /J#53` |
| 4-pdf-objstm-escaped-js | 4 | the same action inside a FlateDecode object stream |
| 5a-pdf-auto-js-unrelated-attachment | 5 | `/OpenAction` script + a text attachment it never references |
| 5b-pdf-auto-js-exports-attachment | 5 | `/OpenAction` script calling `exportDataObject({cName:"f", nLaunch:0})` |
| 6a-docx-hyperlink | 6 | ordinary external hyperlink (negative control) |
| 6b-docx-external-template | 6 | external `attachedTemplate` to an RFC 2606 `.invalid` host |
| 7-docx-macro-declaration-mismatch | 7 | macro-free DOCX declaration carrying a `vbaProject.bin` placeholder |

## 6. Baseline (before any detection change)

- **Tests** (commit `c8bf8dd` + harness): 539 passed, 28 skipped (Linux-only isolation tests).
- **Detection matrix**, commit `1d6db56`, 20 trials, every case deterministic:
  [`docs/evidence/custom-engine-baseline-1d6db56/`](evidence/custom-engine-baseline-1d6db56/matrix.md).

Gaps found (the reason for the first improvement):

| Case | Observed | Why it is wrong |
|---|---|---|
| 5a | PDF scanner **MALICIOUS** via `PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD` (HIGH) | The automatic script (`app.alert(1)`) never touches the attachment; two unrelated indicators were combined into proof |
| 2b | PDF scanner `PDF_AUTO_JAVASCRIPT` | The script runs only on click; "automatic" leaked through the `/OpenAction` page destination to the page's link annotation |
| 2 | YARA-X `PDF_JavaScript_With_Automatic_Action` | The bytes `/AA` belong to a keystroke trigger, which is not automatic |
| 3, 4 | YARA-X SAFE | Byte signatures are blind to escapes/compression; pypdf and C1 already catch both, so normalising for YARA-X would not change any final verdict here (not pursued) |

**Latency** (in-worker scanner durations vs. wall time per scan): every scanner together takes
**1-3 ms** per document; the wall time per scan is **~530-610 ms** (p50). Start-up profile of the
worker's imports on this laptop (3 runs): bare interpreter ~66 ms, `pypdf` ~155-173 ms, `oletools`
+ `msoffcrypto` ~128-138 ms, application scanners incl. YARA-X rule compile ~130-137 ms.

Rejected latency hypotheses (measured, not worth building): YARA-X rule compile is **4-7 ms**
(deserialising precompiled rules ~2 ms), so compiled-rule reuse saves < 1% of a scan. YARA-X
scanning is ~0.3-0.45 ms per document, so `fast_scan` (which may also drop match detail) cannot
matter either.

## 7. Original contribution so far

### Module 1: PDF action chains (`app/engine/pdf_chains.py`)

- **Input**: PDF bytes. **Output**: `PdfChains(chains, attachments, repaired)`, or `None` for
  non-PDFs; `ChainScanError` (fail closed) for unreadable/encrypted/over-limit files.
- **Model**: a chain is one trigger and the actions it starts. Triggers: `/OpenAction`
  (automatic), any `/AA` entry (automatic iff its key is in the PDF scanner's `AUTO_TRIGGERS`),
  `/A` (click), each document-level script in the `/JavaScript` name tree (automatic). Actions:
  the trigger's action and its `/Next` actions, **nothing else** (ISO 32000-1 12.6.2).
- **Algorithm**: (1) depth-first structure walk from the catalog with a `seen` set of
  `(idnum, generation)`, skipping the same bulky keys as the PDF scanner; every trigger key
  starts a chain. (2) Per chain, a breadth walk over `/Next` only, with its own `seen` set (cycles
  are legal syntax) and `raw_get` so references stay references. (3) Each action is described:
  kind, `/JS` presence, and payload, meaning an embedded file it launches (`Launch /F` with `/EF`),
  exports (`exportDataObject`-family call: literal `cName` or `<computed name>`), or opens (`GoToE /T /N`).
- **Bounds**: `MAX_OBJECTS`, `MAX_DEPTH`, `MAX_ACTIONS`, bounded script text; exceeding one raises.

### Module 2: chain findings and correlation (`app/engine/correlate.py`)

Fixed severities per automatic chain (nothing is added up):
`ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT` HIGH (launches/exports an embedded file of this
document), `ENGINE_PDF_AUTO_CHAIN_LAUNCH` HIGH, `ENGINE_PDF_AUTO_CHAIN_OPENS_EMBEDDED_DOCUMENT`
MEDIUM, `ENGINE_PDF_AUTO_CHAIN_SCRIPT` MEDIUM, `ENGINE_PDF_CHAINS_REPAIRED` INFO.

`correlate(report)` reconciles the reference findings, by rule ID:
- supersedes the PDF scanner's `PDF_AUTO_JAVASCRIPT` and `PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD` **only
  if** both the PDF scanner and the chain scanner completed and pypdf repaired nothing; otherwise
  every reference finding stands (fail closed toward the more cautious reading);
- never removes a YARA-X match (a signature can see bytes a parser missed: removing it would be a
  downgrade an attacker could aim for); it only notes when structure does not confirm one;
- records every decision in one INFO finding, `ENGINE_CORRELATION`.

The unified engine = the four reference scanners (unchanged) + `pdf-chains` + `correlate`, run by
`python -m app.worker --engine=unified`. The API never passes that flag, so `/scan` is unchanged.

## 8. Results: reference vs unified (commit `51a5049`, 20 trials each, same session)

Evidence: [`docs/evidence/custom-engine-51a5049/`](evidence/custom-engine-51a5049/) (`reference/`,
`unified/`: `results.json`, `matrix.md`). All 20 trials of every case were identical.

| Case | YARA-X | PDF | Office | Custom | Reference engine | **Unified engine** |
|---|---|---|---|---|---|---|
| 1-pdf-clean | SAFE | SAFE | n/a | SAFE | SAFE | SAFE |
| 2-pdf-form-keystroke-js | SUSPICIOUS | SUSPICIOUS | n/a | SAFE | SUSPICIOUS | SUSPICIOUS |
| 2b-pdf-open-at-page-click-js | SUSPICIOUS | SUSPICIOUS | n/a | SAFE | SUSPICIOUS | SUSPICIOUS (no false "automatic" claim) |
| 3-pdf-escaped-openaction-js | SAFE | SUSPICIOUS | n/a | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS |
| 4-pdf-objstm-escaped-js | SAFE | SUSPICIOUS | n/a | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS |
| 5a-pdf-auto-js-unrelated-attachment | SUSPICIOUS | MALICIOUS | n/a | SAFE | **MALICIOUS** | **SUSPICIOUS** |
| 5b-pdf-auto-js-exports-attachment | SUSPICIOUS | MALICIOUS | n/a | SAFE | MALICIOUS | MALICIOUS (with the chain as evidence) |
| 6a-docx-hyperlink | SAFE | n/a | SAFE | SAFE | SAFE | SAFE |
| 6b-docx-external-template | SAFE | n/a | SUSPICIOUS | SAFE | SUSPICIOUS | SUSPICIOUS |
| 7-docx-macro-declaration-mismatch | SUSPICIOUS | n/a | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS |

The individual-scanner columns come from the reference run. In the unified run the `pdf` column
is computed after correlation removed superseded rules, so it is not a reference measurement.

What this shows, and what it does not:
- On these inert fixtures, the unified engine stops escalating 5a to MALICIOUS while keeping 5b
  MALICIOUS. 5a and 5b differ in exactly one thing (whether the automatic script names the
  attachment), and only the chain model tells them apart. Every other verdict is unchanged.
- The evidence for 5b now names the trigger, the action object and the attachment
  (`catalog /OpenAction: JavaScript (object 7 0) (exports 'f')`).
- It does **not** show detection accuracy on real malware or a false-positive rate on real benign
  PDFs; that needs the labelled corpus and the VM (plan, "Quantitative evaluation").
- Latency: `pdf-chains` adds **0.19-0.39 ms** (p50) of in-worker time per PDF (a second pypdf parse)
  and 0 ms for Office files. The median wall time per scan was **~6 ms higher** (577.8 vs 571.7 ms,
  median of case medians; unified higher in 9 of 10 cases). The source of those 6 ms is not
  isolated. No latency improvement is claimed.

## 9. Untrusted input and isolation (plan 3A)

How the "quarantine buffer" works today (reused, unchanged): `/scan` checks the scan token before
reading a body byte, reads at most 10 MB into memory, compares SHA-256 and size with the token,
hands the bytes to a fresh worker process on stdin and drops its reference afterwards. Nothing is
written to disk. In the API process the only inspection is `detect_format` (magic bytes). All
parsing happens in the worker after containment is applied (Linux: user+network namespace,
capabilities dropped, rlimits on CPU/memory/files/processes, audit hook), and with
`SECURITY_ENGINE_REQUIRE_ISOLATION=1` the worker refuses to analyse anything if a control is
missing. The quarantine is therefore "held in the API's memory, opened only in the worker", and a
file leaves it toward the FilesMagic converter only with a verdict.

Concrete example of a file that passes type validation but must stay isolated: **case 4**. It is a
valid PDF (`%PDF-` header, parsable cross-reference stream) of under 1 KB. Its action lives in a
FlateDecode object stream, so the dangerous part only exists after decompression. A hostile
variant of the same structure can carry a stream that inflates far beyond the upload size
(pypdf is capped at 20 MB per stream here, the custom lexer at 32 MB per document) or trigger a
parser bug in native decompression code. That is why decompression happens only in the worker,
under `RLIMIT_DATA` and the CPU limit, and why a worker crash or timeout gives UNABLE_TO_SCAN, not
SAFE. Office counterpart: **case 6b** passes ZIP and `[Content_Types].xml` validation and is
harmless to our parsers (we never fetch), but Word or LibreOffice opening it, for example in a
downstream converter, would fetch the remote template. Its risk is to the next consumer, so the
verdict must travel with the file.

## 10. Decisions pending

1. **Format-aware worker start-up (latency).** Startup dominates: importing pypdf (~27% of a scan)
   is useless for Office files, oletools+msoffcrypto (~23%) useless for PDFs. The worker loads
   all code *before* containment and before reading the document, because containment forbids
   loading native libraries afterwards. Routing would need the format to be decided by the API
   from magic bytes (untrusted) and passed to the worker; the worker would then have to verify,
   inside isolation, that no other format is present (polyglots) and fail closed if one is.
   Needs the student's and supervisor's agreement before it is built.
2. Office correlation (macro autoexec + external relationships + C4-C6 on the same package parts).

## 11. Known limitations

- Static only: computed JavaScript (`this["export"+"DataObject"]`) is not followed; a data-object
  call is recognised by its method name.
- XFA scripts are not modelled (the PDF scanner flags XFA forms LOW).
- `GoToE` targets are named, not analysed recursively.
- The chain view and the PDF scanner share pypdf, so a pypdf/Acrobat parser differential affects
  both; that is why YARA-X matches are never removed and a repaired structure disables superseding.
- All cases are synthetic and BENIGN by ground truth; they demonstrate indicator handling only.

## 12. PDF corrections (Nov 6, commit `7dc8fe8`)

Evidence: [`docs/evidence/custom-engine-7dc8fe8/`](evidence/custom-engine-7dc8fe8/) (reference and
unified, 20 trials each, same session, 11 cases: case `2c` was added as an over-correction guard).

### 12.1 Investigation

Which YARA-X strings produced `PDF_JavaScript_With_Automatic_Action` (printed from the match
offsets, not assumed):
- case 2: `$auto2` matched `/AA << /K << /S /JavaScript ...`, a form-field keystroke trigger
  (ISO 32000-1 Table 196: runs on user input);
- case 2b: `$auto1` matched `/OpenAction [3 0 R /Fit]`, an inline destination (Table 28: the
  value may be a destination, which shows a page and runs nothing).

So each issue had a structural part (the PDF scanner's inherited "automatic" flag, already
replaced by the chain rules since `51a5049`) and a signature part.

### 12.2 Correction 1: click-only scripts are classified as such

The chain model already excluded them (only `/Next` joins a chain). Added: an explicit INFO finding
`ENGINE_PDF_USER_TRIGGERED_SCRIPT` that names each user-triggered script chain, and regression tests
for a GoTo *action* to the page, an indirect destination array, an outline-item click, and the
over-correction guard (case 2c: the destination page's own `/AA /O` stays automatic).

### 12.3 Correction 2: refined signature `ENGINE_PDF_JavaScript_With_Automatic_Trigger`

Concept: a byte signature cannot parse nested dictionaries, so instead of recognising automatic
triggers more cleverly, it **discounts only occurrences whose bytes prove they are not automatic**:
- `#open > #open_destination`: every `/OpenAction`, minus those directly followed by `[`;
- `#aa > #aa_user_only`: every `/AA`, minus direct dictionaries whose every key is a user-interaction
  trigger (`K F V C E X D U Fo Bl PC PI`, the complement of the PDF scanner's `AUTO_TRIGGERS`) with an
  indirect reference or a non-nested dictionary as value;
- at the scanner's match cap (1000 per pattern) nothing is discounted.

Anything unprovable (indirect `/AA 9 0 R`, an indirect `/OpenAction`, a `>` inside a script, an
unknown key, text in a string) still counts, as in the reference rule. Consequence, tested on every
case and variant: **the refined rule fires only where the reference rule fires.** It runs as the
engine's own YARA-X scanner (`EngineSignatures`, a subclass of the reference `YaraXScanner`: same
metadata enforcement, timeout, match cap, fail-closed handling). `correlate()` replaces the
reference match only when that scanner completed; no parser result is involved, so the signature
evidence stays independent of pypdf.

Reused: YARA-X (matching, regex engine, counts), `YaraXScanner`. Original: the rule and its
counting method, and the correlation step.

Measured limit: YARA-X ends a regex match at about 4 KiB. The proof holds for an `/AA` dictionary
matched in up to 4,092 bytes (a 4,055-byte script); longer ones are not proven, and the rule then
fires as the reference rule does (tested at 4,000 and 5,000 bytes). Form formatting scripts
(`AFNumber_Keystroke(...)`) are under 100 bytes.

### 12.4 Results at `7dc8fe8`

| Case | Automatic script present? | Reference "automatic" claims | Unified "automatic" claims |
|---|---|---|---|
| 2 form keystroke | no | YARA-X (false) | none |
| 2b page destination + click | no | PDF scanner + YARA-X (both false) | none |
| 2c page destination + page `/AA /O` | yes | PDF scanner + YARA-X | chain rule + refined signature |
| 3, 4 escaped / object stream | yes | PDF scanner (YARA-X misses) | chain rule (signature misses: escaped bytes) |
| 5a, 5b | yes | all | chain rule + refined signature |

- False "automatic" rule hits on these 11 cases: reference 3, unified 0; no true claim lost.
- Signature alone: reference rule fires on {2, 2b, 2c, 5a, 5b}, refined on {2c, 5a, 5b}; automatic
  script present in {2c, 3, 4, 5a, 5b}. Synthetic cases only; not a general precision figure.
- Verdicts: unchanged except 5a (MALICIOUS → SUSPICIOUS, from `51a5049`). Cases 2 and 2b stay
  SUSPICIOUS because the reference PDF scanner rates *any* JavaScript MEDIUM (`PDF_JAVASCRIPT`);
  the engine does not change that policy.
- Latency: `yara-x-engine` 0.30-0.36 ms p50 per document, `pdf-chains` ≤ 0.43 ms. Wall time per scan
  +9 ms (median of case medians 577.0 → 586.1 ms). Accounted for: importing `app.engine` (mostly
  compiling the second rule set) measured 7.1-8.4 ms in 5 runs.

### 12.5 Linux-only isolation tests: not run at the time (superseded by section 15)

28 tests in `tests/test_worker_linux.py` (namespaces, capabilities, rlimits, audit hook,
tunl0 fallback) skip on Windows. This machine has neither WSL nor Docker. The suitable
environment is the repository's CI job `backend-linux` (Ubuntu 24.04, `FM_REQUIRE_LINUX_TESTS=1`,
which turns those skips into failures), run on push. Not pushed: the branch is not excluded in
`frontend/vercel.json`, so a push would likely create a Vercel preview deployment. **Isolation is
therefore not validated for these commits.** The unified engine changes no isolation code; the
worker gained only the `--engine=unified` scanner selection before containment is applied.

## 14. Office: VBA call-graph analysis (Nov 6, commit `7d9f69c`)

### 14.1 Threat and gap

A macro attack needs code that runs without being asked (an automatic entry: `AutoOpen`,
`Document_Open`, `Workbook_Open`, ActiveX event handlers) and code that does something dangerous
(run a program, download, WMI, inject code). The reference Office scanner raises
`OFFICE_MACRO_AUTOEXEC_EXECUTION` (HIGH) when olevba finds both **anywhere in the same project**:
the macro counterpart of PDF case 5a. A benign workbook whose `Workbook_Open` only sets up the
sheet and whose unrelated button handler starts a program is rated MALICIOUS.

### 14.2 Algorithm (`app/engine/vba_chains.py`)

1. Lexing: line continuations collapsed (olevba `vba_collapse_long_lines`), comments (apostrophe,
   `Rem`) removed, string contents blanked. The literals of the code part are kept per line, so a
   comment can never resolve a call.
2. Procedures: `Sub`/`Function`/`Property` blocks up to their `End`, and `Declare ... Lib` lines as
   external functions. An aliased declaration (`OpenIt ... Alias "ShellExecuteA"`) is how a
   harmless-looking call site hides a dangerous function.
3. Capabilities: olevba's `VBA_Scanner` on each procedure's text, keeping the descriptions the Office
   scanner's `STRONG_VBA_BEHAVIOUR` rates strong, i.e. the reference's own definition of dangerous.
4. Edges: any identifier equal to a procedure name (deliberately loose: a path may be over-reported,
   never hidden); `Run`/`OnTime`/`OnKey`/`OnAction`/`CallByName` with a literal naming a procedure
   (`"Module1.Proc"`, `"'Book.xlsm'!Module1.Proc"`); `AddressOf Proc`.
5. Entries: procedure names matching olevba's `AUTOEXEC_KEYWORDS` / `AUTOEXEC_KEYWORDS_REGEX`.
6. Breadth-first search from each entry. Outcomes:
   - **linked**: a procedure with a capability is reached; the path is reported;
   - **undetermined**: none reached, but a reachable procedure makes a dynamic call (`OnKey`,
     `CallByName`, ... with a name that is not a known procedure; `Evaluate`, `ExecuteExcel4Macro`;
     self-modifying code via `VBProject`, `CodeModule`, `AddFromString`, ...), or the project has
     a gap: unbalanced blocks, a dangerous keyword outside any procedure, a capability or automatic
     keyword olevba reports that no procedure accounts for, XLM macros, or a container that is not
     an OLE VBA project or could not be extracted;
   - **no-path**: none reached and none of the above.

### 14.3 What correlation does with it, and why it never lowers the verdict

`OFFICE_MACRO_AUTOEXEC_EXECUTION` is **never removed**. Linked confirms it (the path is a HIGH engine
finding); no-path and undetermined keep it, with an INFO finding saying why. Reason, from the
installed olevba source (`VBA_Parser.detect_vba_stomping`): VBA stomping, where the source is
replaced while the compiled P-code that Office may execute stays malicious, is checked only for
files on disk, and the isolated worker writes none. So "no-path" is true of the source and
unverified for what runs. A consequence for the reference too: its `VBA Stomping` check never
runs in this engine.

### 14.4 Reused vs original

Reused (oletools 0.60.2, BSD-2): `VBA_Parser.extract_macros`, `VBA_Scanner`, `AUTOEXEC_KEYWORDS`,
`AUTOEXEC_KEYWORDS_REGEX`, `vba_collapse_long_lines`. Reused (this repository): the Office
scanner's `STRONG_VBA_BEHAVIOUR`, `identify`, `read_member`, ZIP limits and `clean`. Original: the
lexer, the procedure and call-graph model, resolution of named and `AddressOf` calls, the
three-outcome search with its incompleteness rules, and the correlation policy.

### 14.5 Tests and what they show

`tests/test_vba_chains.py`, 33 tests. All VBA is inert Python strings (the "dangerous" lines are
`Shell "placeholder"`). No VBA project or macro-bearing document is built: a stand-in replaces only
olevba's container parsing, and keyword analysis stays real olevba. Covered:
- related (transitive, cross-module) and unrelated procedures, names in comments and strings, cycles;
- indirect calls resolved by literal (`Run` with plain, module-qualified and workbook-qualified
  names, `OnTime`, `AddressOf`); dynamic calls (`OnKey`, `CallByName`, `Evaluate`, `VBProject`);
  dynamic calls outside the reachable part (ignored); an established path winning over a dynamic call;
- an aliased `Declare`; incomplete graphs (missing `End`, stray `End`, module-level `CreateObject`,
  an automatic keyword with no procedure); extraction failures; non-OLE VBA parts; broken ZIPs
  (fail closed as malformed input);
- the unified engine on all three outcomes: the reference HIGH stays, and the verdict equals the
  reference's (MALICIOUS) every time.

Finding from the tests: olevba lists `Run` itself under "May run an executable file or a system
command", so `Application.Run procName` makes its own procedure a capability node and the outcome
is linked, not undetermined (the cautious direction, and the reference's own definition).

What this does **not** show: no measurement on real documents (none are built, by decision), no
change in any verdict, nothing about P-code. On the case matrix (`docs/evidence/custom-engine-7d9f69c/`)
every PDF and Office result is identical to `7dc8fe8` for both engines; `vba-chains` takes at most
0.15 ms p50 and reports case 7 as undetermined (its `vbaProject.bin` placeholder is not an OLE
project). Wall time in this run: +14 ms against the reference (574.2 to 588.5 ms), of which about
8 ms is engine start-up (12.4); the rest is not isolated.

## 15. Linux CI (Nov 6, run 42259767395, commit `2721a25`)

Deployment safeguards checked before the push: `frontend/vercel.json` now disables Git deployments
for this branch as well as `security/malware-research-hardening`. The connected Vercel project
(`filesmagic-security-lab`) honours that file: the excluded branch's Nov 3 pushes have no Vercel
status or deployment, while this branch's earlier push (`c22fe64`, before the exclusion) got a
Preview. Render has `autoDeployTrigger: "off"`; the only workflow builds and tests and deploys
nothing; there are no repository webhooks. Pushed content: code, tests and evidence JSON (versions,
timings, rule IDs; no document bytes, no secrets). The EICAR/Didier files are not committed.

| Job | Result |
|---|---|
| Backend (Linux, Python 3.11, non-root), `FM_REQUIRE_LINUX_TESTS=1` | success: **633 passed, 0 skipped**, including the 28 Linux isolation tests; unprivileged user+network namespaces available |
| same job, rerun with the `tunl0` fallback device (Render condition) | success: 28 passed |
| Production image (Docker, non-root, `--network none`) | success; under Docker's default seccomp `process`, `rlimits`, `audit_hook` are true and `network_namespace`, `network_verified`, `capabilities_dropped` false (reported, not required, by design) |
| Security Lab (typecheck, lint, build, audit) | success |
| Vercel | no status and no deployment for `2721a25` |

Conclusion allowed: the worker's Linux isolation controls pass their tests on the GitHub Ubuntu
24.04 runner, whose AppArmor user-namespace restriction the workflow relaxes. Not shown: isolation on
Render or on the evaluation VM; and the production image gets no network namespace under Docker's
default seccomp.

## 16. Learning journal

- Nov 6: `pypdf`'s `dict[key]` silently resolves indirect references. The first chain test caught
  a `/Next` cycle running an action twice because the cycle guard tracks object IDs and the
  resolved value no longer had one. Fix: `raw_get`. Lesson: cycle detection must operate on
  identities, so the access path must preserve them.
- Nov 6: a signature can be made more precise without becoming weaker if it only *subtracts*
  occurrences the bytes disprove. Counting (`#a > #b`) does that in YARA's condition language;
  regex cannot balance nested `<< >>`, so the proof gives up on anything it cannot match.
- Nov 6: YARA-X regex matches end at about 4 KiB (measured by bisection: 4,092 bytes).
- Nov 6: read the dependency, not its reputation: olevba's stomping check returns False for
  in-memory files, so a check the reference appears to make never runs in an isolated worker.
- Nov 6: profiling before optimising. The plan listed compiled-rule reuse and `fast_scan` as
  latency ideas; measurement showed YARA-X is < 2% of a scan. The real cost is process start-up.
