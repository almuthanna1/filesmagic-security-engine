# Custom detection rebuild: architecture audit (Phase 1)

Baseline: `origin/main` at **b6774be** ("Merge pull request #28 ... pdf-dangling-outline-coverage"),
tagged locally as `baseline/pre-custom-rebuild`. Working branch: `feature/custom-malware-detection-rebuild`,
created from that commit. The working tree was clean (the checkout was on `docs/eicar-didier-research`,
which was not touched).

Baseline regression suite on Windows (Python 3.14.3, `.venv`): **1203 passed, 43 skipped** in 48 s.
The 43 skips are Linux-only isolation tests (`test_worker_linux.py`, `test_vm_scripts.py`) and the
opt-in pinned qpdf fixtures. Baseline detection evidence, captured before any change:
`docs/evidence/custom-detection-rebuild/baseline-b6774be/` (synthetic case matrix through the real
worker, both benign corpora through both engines).

## 1. Runtime structure at baseline

Two scanner rosters existed, selected per request by `?engine=`:

| Engine | Roster (`app/scanners/__init__.py`, `app/engine/__init__.py`) | Default |
|---|---|---|
| `reference` | `yara-x`, `office`, `pdf`, `custom` | yes, unless `SECURITY_ENGINE_PUBLIC_UNIFIED_ONLY=1` |
| `unified` | the four above + `yara-x-engine`, `pdf-chains`, `pdf-integrity`, `vba-chains`, `ooxml-links`, `word-fields`, then `correlate()` | required for Conversion Engine tokens |

So the Unified Engine imported the reference scanners as its first four members; `correlate()`
then reconciled findings by `(scanner, rule_id)`, dropping or merging some reference findings when
an engine scanner had examined the same evidence more precisely.

The Conversion Engine (`filesmagic-engine/app/security_gate.py`, read only) pins `engine == "unified"`,
the full 40-character `commit`, and the **exact sorted 10-scanner roster** in the signed receipt
(`ROSTER`, line 79). Any roster change therefore needs a coordinated Conversion Engine release.

## 2. Classification of every scanner and engine module

Legend: **C** custom detection algorithm, **T** third-party detection dependency, **P** permissible
parsing dependency, **I** infrastructure, **R** obsolete or redundant.

| Module / scanner | Class | Third-party imports | What decides the finding |
|---|---|---|---|
| `app/scanners/yarax.py` (`yara-x`) | **T** | `yara_x` (Compiler, Scanner) | YARA-X matches `app/rules/filesmagic.yar` |
| `app/engine/__init__.py` `EngineSignatures` (`yara-x-engine`) | **T** (rules **C**) | `yara_x` via `YaraXScanner` | YARA-X matches our refined rule `app/engine/rules/pdf.yar` |
| `app/scanners/office.py` (`office`), VBA part `vba_findings()` lines 114-156 | **T** | `oletools.olevba.VBA_Parser.detect_macros/analyze_macros` | olevba's `AutoExec`, `Suspicious`, `Hex/Base64/Dridex/VBA obfuscated String` classifications, filtered by our `STRONG_VBA_BEHAVIOUR` regex |
| `app/scanners/office.py`, OLE/OOXML structure (everything else) | **C** + **P** | `olefile`, `msoffcrypto` (`is_encrypted`), `oletools.oleobj.OleNativeStream`, `defusedxml`, `zipfile` | our rules: ZIP limits, path traversal, duplicates, external relationship classification, Equation Editor CLSID, Ole10Native extension check, DDE fields and links |
| `app/scanners/pdf.py` (`pdf`) | **C** + **P** | `pypdf` (PdfReader, generic objects) | our walk of the object graph: JavaScript, automatic triggers, Launch, attachments, coverage |
| `app/scanners/custom/*` (`custom`) | **C** | `defusedxml`, `zipfile`, `zlib` only | own PDF lexer (C1), OOXML declaration/relationship/ZIP checks (C4-C6) |
| `app/engine/pdf_chains.py`, `pdf_attachments.py`, `c2pa.py` (`pdf-chains`) | **C** + **P** | `pypdf`, `defusedxml` | own action-chain graph, attachment verification, C2PA manifest inspection |
| `app/engine/pdf_integrity.py` (`pdf-integrity`) | **C** + **P** | `pypdf` | own stream-coverage accounting |
| `app/engine/vba_chains.py` (`vba-chains`) | **C** graph, **T** capabilities | `olevba.VBA_Parser.extract_macros/detect_*` (**P**), `vba_collapse_long_lines` (**P**, trivial), `VBA_Scanner` (**T**), `AUTOEXEC_KEYWORDS`, `AUTOEXEC_KEYWORDS_REGEX` (**T**) | own procedure graph, call resolution and BFS; but *which procedures are entries* and *which have a capability* came from olevba's keyword tables |
| `app/engine/ooxml_links.py` (`ooxml-links`) | **C** | `defusedxml`, `zipfile` | own activation / relationship graph |
| `app/engine/word_fields.py` (`word-fields`) | **C** | `defusedxml` | own field-code parser (C7) |
| `app/engine/correlate.py` | **C** | none | own evidence reconciliation |
| `app/decision/`, `app/worker.py`, `app/auth.py`, `app/receipts.py`, `app/main.py`, `app/models.py` | **I** | FastAPI, Pydantic, `cryptography` | verdict rules, isolation, tokens, signed receipts |
| `PDF_JavaScript_With_Automatic_Action` (in `filesmagic.yar`) | **R** | | always dropped by `correlate()` when `yara-x-engine` completed: computed and discarded on every unified scan |
| reference roster as a separate runtime | **R** | | not used by the Conversion Engine (`ENGINE_NOT_APPROVED` for `conversion` issuer) |

## 3. Exact third-party detection code paths to replace

1. **YARA-X signature matching.** `app/scanners/yarax.py:30-99` (`compile_rules`, `YaraXScanner.scan`);
   `app/engine/__init__.py:20-27` (`EngineSignatures`). Rules: 9 in `filesmagic.yar`, 1 in `pdf.yar`.
   Features in use: fixed strings, `nocase`, `wide`, regular expressions (two with bounded
   repetition over PDF delimiters), `$x in (0..N)`, `#x` counts compared with each other,
   `any of (...)`, `uint16/uint32` at fixed and computed offsets, and the scanner settings
   `max_matches_per_pattern(1000)` and `set_timeout(10)`.
   Replacement requirements: overlapping start-offset semantics (counts), YARA-X's regex
   match-length bound (an existing test already depended on it at "about 4 KiB"), saturating
   counts at the cap, fail-closed load/scan errors, unchanged rule IDs and severities.
2. **olevba macro classification in the Office scanner.** `app/scanners/office.py:114-156`:
   `VBA_Parser.detect_macros()` (presence, P) and `analyze_macros()` (T). Rule IDs produced:
   `OFFICE_MACROS_PRESENT` LOW, `OFFICE_MACRO_AUTOEXEC` MEDIUM, `OFFICE_MACRO_DANGEROUS_CAPABILITY`
   MEDIUM, `OFFICE_MACRO_SUSPICIOUS_KEYWORDS` LOW, `OFFICE_MACRO_OBFUSCATION` LOW,
   `OFFICE_MACRO_AUTOEXEC_EXECUTION` HIGH, `OFFICE_VBA_UNPARSED` LOW.
3. **olevba keyword tables in the call graph.** `app/engine/vba_chains.py:49` and its uses:
   `_strong()` (`VBA_Scanner(code).scan()`), `_ENTRY_NAMES` / `_ENTRY_PATTERNS`
   (`AUTOEXEC_KEYWORDS(_REGEX)`), the "olevba reports X but no procedure accounts for it" and
   "automatic-entry keyword" consistency checks, and `parse()` (`vba_collapse_long_lines`).

Permissible and kept: `VBA_Parser.extract_macros()`, `detect_vba_macros()`, `detect_xlm_macros()`
(MS-OVBA decompression, OLE stream walking, BIFF record listing: extraction only), `olefile`,
`OleNativeStream` (Ole10Native header parsing), `msoffcrypto.OfficeFile.is_encrypted()` (header
parsing), `pypdf`, `zipfile`, `zlib`, `defusedxml`.

## 4. Behavioural facts the replacements must respect

- olevba's `AUTOEXEC_KEYWORDS_REGEX` counts *any* `\w+_Click`, `\w+_Change`, `\w+_MouseMove` ...
  as automatic execution, and its "May run an executable" list includes `Run`, `vbHide`,
  `shell32`, `DoIt`. `vba_chains.py` already documented these as ambiguous (AMBIGUOUS,
  CONFIRMED_BY), but the Office scanner's HIGH rule did not: any entry keyword plus any such
  keyword anywhere in the project produced MALICIOUS.
- XLM (Excel 4.0) macros reach olevba's analysis as text produced by oledump's `plugin_biff`
  (`extract_macros` yields module `xlm_macro`). They are not VBA and are not in the call graph.
- VBA stomping (source replaced, P-code kept) can only be checked by olevba on files on disk; the
  worker writes no files. Absence of suspicious *source* is never evidence about P-code.
- The worker runs scanners sequentially in one isolated process; extraction is repeated by
  `office` and `vba-chains` on the same bytes.

## 5. Implementation plan (executed in this order)

| Phase | Change | Gate |
|---|---|---|
| 2 | `app/engine/signatures.py` + `signature_rules.py`: own matcher, the 9 non-redundant rules ported, one `signatures` scanner replacing `yara-x` and `yara-x-engine` in the unified roster | differential test against YARA-X on > 5,000 inputs; full suite green |
| 3 | `app/engine/vba_analysis.py`: own tokenizer, normaliser, entry-point table, capability rules in context, bounded constant folding / deobfuscation; Office scanner and `vba_chains` use it; `VBA_Scanner`/`AUTOEXEC_*`/`analyze_macros` no longer imported | per-rule tests; coverage-parity test against olevba's tables; every changed baseline outcome listed |
| 4 | PDF/Office consolidation: remove duplicated extraction, keep findings stable | suite + frozen matrix |
| 5 | retire `reference` runtime (`engine=reference` rejected explicitly, default `unified`), drop `yara-x` from runtime requirements (kept as a dev-only parity oracle) | API tests, roster tests |
| 6 | full regression and comparison with the baseline evidence | report |
| 7 | capstone guide and integration plan (Conversion Engine roster pin is the one required code change on that side) | |
