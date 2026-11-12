# pypdf 6.19.0 -> 7.0.1: dependency upgrade evidence

Why: pypdf 6.19.0, pinned at `e2eb2c7`, has 18 published advisories (pip-audit, 2026-11-12), all
denial of service through crafted PDFs. 6.21.4 fixes all 18. 7.0.1 fixes them as well, adds the
7.0.0 hardening (object streams whose offsets are not strictly increasing are blocked, stricter image
size limits, bounded XFA decoding), and has no known advisories. Nothing else in `requirements.txt`
changes. pip-audit reports no known vulnerabilities for the whole pinned set at either version.

The base is `e2eb2c7`, the release validated in the C2PA accuracy study and deployed to staging. The
frozen Capstone release (`2d586f6`, tag `custom-engine-freeze-2026-11-09`) is not touched.

## Compatibility

- Engine code (`app/`): no change needed. It uses `PdfReader`, `apply_configuration`,
  `PasswordType`, `pypdf.errors.PdfReadError`, the generic object classes and the `pypdf` logger.
  All of these behave the same on 7.0.1.
- One test fixture used `PdfWriter.add_js`, which was removed in 7.0.0. It now calls
  `add_open_action(JavaScript(...))`, which is the call `add_js` made in 6.x, so the fixture builds the
  same PDF on both versions (`eab1f20`).
- 7.0.0 makes `PdfWriter` file identifiers non-deterministic. The engine never writes PDFs, so this
  affects only test and evaluation fixtures, and no test depends on it.

## Results

| Suite | pypdf 6.19.0 | pypdf 7.0.1 |
|---|---|---|
| `pytest` (Windows, Python 3.12) | 1107 passed, 41 skipped | 1107 passed, 41 skipped |
| Linux CI on this branch (non-root, isolation and tunl0 tests, production image) | see the branch's CI run | see the branch's CI run |
| Accuracy: whole corpus, both engines, 3 trials | baseline | **0 of 504 results differ** |
| Accuracy, 6.21.4 run for comparison | baseline | 0 of 504 results differ |

The accuracy check is `evaluation/dependency_regression.py`. It uses the same code tree with two
virtual environments that differ only in pypdf, and the 252 samples of the C2PA accuracy study. That
set comprises:

- the C2PA corpus;
- the earlier PDF accuracy corpus, including the private D1-D3 and L01-L55 documents, checked against
  their committed hashes;
- the 29-file benign corpus;
- `evaluation.cases` (16) and `field_cases()` (6).

For every sample and both engines it compares the verdict, every finding with its description and
evidence, every scanner's status, and determinism.

- Files: `regression-6.19.0-to-7.0.1.{md,json}` and `regression-6.19.0-to-6.21.4.{md,json}` hold sample
  IDs and counts only.
- Per-sample results quote private documents, so they stay local:
  - `results.json` for 7.0.1: SHA-256 `47cb9df7dbd19ebe...`
  - `results.json` for 6.21.4: SHA-256 `f66dc445880e2491...`
- Speed is unchanged: the sum of the fastest trials is 123.9 s on 7.0.1 against 126.4 s for the
  unified engine on 6.19.0.

The end-to-end gate checks and the production rehearsal against this build run in the conversion
engine repository (`filesmagic-engine`, `.github/workflows/scan-gate-e2e.yml`) with this commit pinned.
