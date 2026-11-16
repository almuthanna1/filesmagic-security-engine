# Frozen evaluation evidence: false-positive fixes

The synthetic matrix again, after the benign-corpus false-positive fixes. It is what
`tests/test_api_engines.py` replays. The earlier evidence, `../custom-engine-1668326/`, is unchanged.

| Item | Value |
|---|---|
| Code | the commit that adds this folder: `engine_commit` in `results.json` is its parent, `812bb7d`, and `working_tree_dirty: true` is the fixes of that commit (`app/engine/file_paths.py`, `pdf_attachments.py`, changes in `correlate.py`, `ooxml_links.py`, `pdf_chains.py`) plus the uncommitted EICAR/Didier study documents, which the harness does not read |
| Run | 2026-11-08 05:3x UTC, Windows 11 laptop, Python 3.14.3, 20 trials per case per engine, reference first |
| Cases | the same 16 inert fixtures (`evaluation.cases.cases()`) |

## Changes from `custom-engine-1668326`

| Engine | Case | Verdict | Rules |
|---|---|---|---|
| reference | all 16 | unchanged | unchanged |
| unified | 5a | SUSPICIOUS (unchanged) | `PDF_EMBEDDED_FILE` (pdf) and `PDF_Embedded_File` (yara-x), both LOW, merged into `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` (LOW) |
| unified | 5b | MALICIOUS (unchanged) | the same merge; `ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT` (HIGH) unchanged |
| unified | 6c | SUSPICIOUS (unchanged) | `OFFICE_EXTERNAL_AUTOLOAD` (office, MEDIUM) merged into `ENGINE_OFFICE_EXTERNAL_ON_OPEN` (MEDIUM) |
| unified | other 13 | unchanged | unchanged |

Every case is deterministic over its 20 trials. Reproduce with `python -m evaluation.cases --trials 20
[--engine unified] --out <dir>` at the commit that adds this folder.
