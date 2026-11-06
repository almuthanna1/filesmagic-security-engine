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
| Format-aware worker start-up (latency) | proposed, needs a security decision (section 10) |
| YARA-X compiled-rule reuse; YARA-X `fast_scan` | rejected by measurement (section 6) |
| Office correlation (macro + relationship + C4-C6) | proposed, next |

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

## 12. Learning journal

- Nov 6: `pypdf`'s `dict[key]` silently resolves indirect references. The first chain test caught
  a `/Next` cycle running an action twice because the cycle guard tracks object IDs and the
  resolved value no longer had one. Fix: `raw_get`. Lesson: cycle detection must operate on
  identities, so the access path must preserve them.
- Nov 6: profiling before optimising. The plan listed compiled-rule reuse and `fast_scan` as
  latency ideas; measurement showed YARA-X is < 2% of a scan. The real cost is process start-up.
