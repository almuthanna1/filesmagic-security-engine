# Combined accuracy regression, integration v1

Produced by `evaluation/combined_regression.py` on Windows 11 with Python 3.12. The analysis is in
[security-integration-v1-readiness.md §1](../../security-integration-v1-readiness.md).

- `run1-three-builds/`: candidate vs `90718ff` vs `840a300`, 3 trials. The candidate was `ca8ca9a` with the
  integration v1 Phase 3 edits uncommitted (`dirty: True`). The memory figures in this run read 0: the Windows
  memory call was mis-declared, and was fixed before the re-run.
- `rerun-1e86627/`: the candidate at the committed `1e86627` (clean), 1 trial; `memory.json` is the fixed
  memory pass, one fresh process per sample. Its verdicts, reasons and authorizations are identical to run 1
  for all 252 samples × 2 engines.

`results.json` (per-sample findings, which quote private local documents) is kept local and not committed.
