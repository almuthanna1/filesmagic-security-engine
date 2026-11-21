# Custom detection rebuild: regression report (Phase 6)

Baseline: `b6774be` (tag `baseline/pre-custom-rebuild`), unified engine with YARA-X and olevba's
heuristics. After: `2308739` (Phase 5), the unified engine with our own signature matcher and VBA
analysis. Every number below was produced by a command in this repository; the raw output is in
`docs/evidence/custom-detection-rebuild/`. All inputs are inert synthetic fixtures or the approved
benign corpora. No macro or embedded code was executed: VBA is read as text, never run.

## How to reproduce

```
A=docs/evidence/custom-detection-rebuild/after-2308739
B=docs/evidence/custom-detection-rebuild/baseline-b6774be
python -m evaluation.cases --trials 3 --engine unified --out $A/cases-unified
python -m evaluation.benign_corpus.local --out $A/benign-files.json
python -m evaluation.benign_corpus.local --out $A/benign-independent.json --dir evaluation/benign_corpus/independent
python -m evaluation.compare_baseline $B $A                       # -> $A/comparison.txt
git worktree add --detach <dir> baseline/pre-custom-rebuild
python -m evaluation.vba_cases --out $A/vba-cases --baseline-tree <dir> --trials 3
python -m evaluation.rebuild_regression $B $A --out $A/regression-numbers.json
```

## 1. Detection outcomes

| Corpus | Inputs | Verdict changes | Finding changes |
|---|---|---|---|
| Synthetic case matrix (`evaluation/cases`) | 16 | 0 | 3 (intended merge, below) |
| Benign files (`benign_corpus/files`) | 29 | 0 | 0 |
| Benign independent (`benign_corpus/independent`) | 4 | 0 | 0 |
| VBA case matrix (`evaluation/vba_cases`, new) | 16 | 6 (all MALICIOUS → SUSPICIOUS, intended) | see §2 |

No input became SAFE that was not SAFE before, and no input was newly UNABLE_TO_SCAN.

## 2. Every changed finding

**Synthetic cases 2c, 5a, 5b**: `signatures:ENGINE_PDF_JavaScript_With_Automatic_Trigger` is no
longer a separate finding. The chain rules (`pdf-chains`) confirm the same automatic script, and
correlation merges the signature into that chain finding, recording it in ENGINE_CORRELATION evidence
as "merged ... counted once" (Phase 4). The verdicts are unchanged: 5a stays SUSPICIOUS because the
unrelated attachment is not treated as part of the script chain, and 5b stays MALICIOUS because the
script exports the attachment. If the chain rules fail or see a repaired file, the signature is kept.

**VBA cases.** The baseline's VBA results came from olevba's keyword tables. The rebuild reads the
VBA itself: it tokenizes the code, follows calls from the entry points, and resolves names.

| Case | Before → after | Why it changed |
|---|---|---|
| v05 `vbHide` as a constant | MALICIOUS → SUSPICIOUS | olevba treats the word `vbHide` as execution. Here it is only a value assigned to a variable; nothing runs. |
| v06 `Application.Run "Helper"` | MALICIOUS → SUSPICIOUS | olevba treats the word `Run` as execution. `Application.Run` starts another macro in the same project, and that macro is analysed in its own right. |
| v07 `shell32` folder API | MALICIOUS → SUSPICIOUS | olevba matches the DLL name `shell32`. The rebuild decides on the function actually declared, `SHGetFolderPathA`, which only reads a folder path. |
| v08 user `Sub Shell` | MALICIOUS → SUSPICIOUS | The project defines its own `Shell` procedure, which hides the built-in one, so a call to `Shell` is reported as possible only (LOW). |
| v14 `obj.Run` on an unknown object | MALICIOUS → SUSPICIOUS | The type of `obj` cannot be determined, so the call is reported as possible only. |
| v04 harmless macro | SUSPICIOUS (unchanged) | A LOW keyword finding was dropped. "Macros present" still keeps the file from being SAFE. |
| v02, v09, v10, v12 | MALICIOUS (unchanged) | `vba-chains` now reports the entry → capability chain (HIGH). In the baseline it missed these four. For v02, the cause was that olevba's module names kept their `.bas` extension, so `Module2.Tool` never resolved. v09, v10 and v12 had no baseline chain at all. |
| v09, v10, v11 | MALICIOUS (unchanged) | olevba's generic LOW keyword finding was replaced by specific findings: decoded obfuscation for v09, and the reachable chain for v09 and v10. |

The five cases with no change (v01, v03, v13, v15, v16) produce identical non-INFO findings in both
trees. The renamed scanner (`yara-x` is now `signatures`) is mapped, not counted as a change.

## 3. False positives

The benign corpora show no change: 0 of 33 files changed verdict or finding. The five VBA verdict
changes in §2 are removals of false positives. The patterns behind them are common in harmless
macros: `vbHide` used as a constant, `Application.Run`, `shell32` folder APIs, and a procedure
named `Shell`. The real-world false-positive rate is not measured here, because the approved
corpora contain no VBA (see Limitations).

## 4. Coverage

- The signature matcher agrees with YARA-X on all 5,328 inputs of the parity corpus. These are the
  rule triggers, the benign controls, the case matrix, both benign corpora, and 3,000+ fuzzed
  inputs, including the edge cases at offset ranges and the 4,095-byte window. Every rule fires at
  least once (`tests/test_signatures.py`).
- The VBA entry-point tables match olevba's AUTOEXEC tables. Two entries are deliberately
  different and documented: `auto_ope` (a misspelling in olevba's list) and the close events.
  `Workbook_Close` is classified as a closing event, not as running on open
  (`tests/test_vba_analysis.py`).
- Rebuild gains: qualified calls across modules, user procedures that hide built-ins, static
  folding of `StrReverse`, `Chr` and `Replace` (with a size bound), `CallByName` with a constant
  method name, and methods resolved on objects created with a constant ProgID.
- Not covered, before or after: P-code that differs from the source (VBA stomping) and XLM macro
  logic. For XLM, only function names are detected. Section 1 of the capstone guide lists all
  limitations.

## 5. Determinism

Every input was scanned 3 times in each tree. All synthetic cases and all VBA cases produced
identical verdicts and findings every time (`deterministic: true`), in both trees.

## 6. Latency

| Measurement | Baseline | After |
|---|---|---|
| Synthetic cases, median time inside the worker (sum of scanner medians) | 3.56 ms | 3.45 ms |
| Synthetic cases, slowest case inside the worker | 5.72 ms | 5.34 ms |
| Synthetic cases, median wall time per scan (process start-up included) | 656 ms | 623 ms |
| VBA cases, median wall time per scan | 726 ms | 631 ms |

The wall times include starting the isolated worker process, which dominates them. The VBA-case
"baseline" timing also includes starting a Python interpreter in the baseline tree, so the two
columns are only roughly comparable.

**Signature matcher compared with YARA-X**, on the parity corpus (5,328 inputs, 1.79 MB, best of 3):

| | Time |
|---|---|
| Our matcher | 48.8 ms |
| YARA-X, a new `Scanner` per file (how the retired `app/scanners/yarax.py` used it) | 1,471.7 ms |
| YARA-X, one reused `Scanner` (matching cost only) | 8.5 ms |

YARA-X's matching itself is about 6 times faster than ours. As it was integrated, though, the cost
of building a scanner for every file dominated, so the retired integration was slower per file.
At the service's 10 s deadline, neither is near a limit on these inputs.

## 7. Memory

- Our matcher's Python heap peak over the whole parity corpus is 1,107 KiB (tracemalloc).
  tracemalloc does not see YARA-X's native allocations, so no comparable YARA-X figure is reported.
- The worker's own memory was **not measured**. On this Windows host, the harness records
  `worker_memory_measured: false`. The Linux CI controls (rlimits) bound it, but they produced no
  numbers here. Removing the `yara_x` native module (verified absent from `sys.modules` by
  `test_the_service_never_imports_a_retired_detection_dependency`) can only reduce the worker's
  footprint, but that is not a measurement.

## 8. Test suite

`pytest`: 1270 passed, 43 skipped, at `2308739`. The skips are Linux-only isolation tests and
corpora that are not present.

## Limitations of this regression

- The benign corpora contain no VBA, so the VBA comparison rests on the 16 synthetic cases. Each
  was built to exercise one behaviour, so they show that the behaviour changed as intended, not
  how often it occurs in real documents. Before integration, a VBA-bearing benign corpus would be
  the most useful addition.
- In v14 the verdict is lowered because the object type is unknown. A real `WScript.Shell` object
  obtained in a way the analysis cannot follow (for example `GetObject` or a parameter) would also
  be SUSPICIOUS, not MALICIOUS. That is a deliberate trade-off with a real consequence: a
  MALICIOUS file can never be converted, but a SUSPICIOUS file is converted once the user
  explicitly chooses to continue (`app/decision`). The five cases lowered in §2 (v05–v08, v14)
  therefore move from "blocked" to "converted with explicit consent". A file with macros is never
  SAFE.
- The latency numbers come from one Windows laptop, with no Linux sandbox.
