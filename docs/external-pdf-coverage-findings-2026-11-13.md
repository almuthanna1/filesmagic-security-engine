# External PDF validation: encryption and malformed-content coverage

**Date:** 2026-11-13 (UTC scan records)  
**Status:** Observed on the standalone **Render research staging engine**, unified engine 0.2.0, commit `ccdb462065fcf3140e5a2295f3754f3c19324ab0`. **Open pre-production security review.**  
**Scope:** Standalone research engine only. FilesMagic's production conversion pipeline is not integrated with it. No genuine malware was submitted. This is a **post-freeze addendum**; do not merge these findings into the frozen Nov 9 `eda2a08` evaluation totals.

## Executive assessment

Two source-pinned qpdf regression fixtures returned `SAFE` with `complete=true`, no scanner failures, and required isolation controls satisfied:

1. An **encrypted PDF** produced `CUSTOM_PDF_COVERAGE_LIMITED` (INFO), explicitly reporting that the custom byte-level scanner could not inspect encrypted strings/streams, while other PDF scanners decrypted the file using an empty user password.
2. A **damaged-data PDF** produced zero findings, even though the fixture includes an LZW-compressed page-content stream. The security scanners deliberately skip ordinary page-content streams and therefore do not establish that its compressed data will decode successfully in a downstream converter.

**Risk:** `complete=true` currently means each applicable scanner *ran*, not that every security-relevant or conversion-relevant byte was validated. `SAFE` means no findings above INFO. A future conversion gate must not silently equate either value with full content coverage. This is a **high-priority potential fail-open design gap**, **not a demonstrated exploit or confirmed malware bypass**. Whether each individual `SAFE` verdict is wrong depends on the required coverage contract and independent inspection of the fixture contents.

## Evidence A: qpdf V4-aes.pdf (validation-24)

- Pinned source: [qpdf fixture](https://github.com/qpdf/qpdf/blob/4eba95899886e851cc41d76886483b347612f2a8/qpdf/qtest/qpdf/V4-aes.pdf)
- Pinned and scanned SHA-256: `1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240` (**matched**).
- Security Lab request: `9db6839ce4584ccb`, recorded `2026-11-13T17:46:05.368Z`.
- Observed: `SAFE`; `complete=true`; 5/5 applicable scanners completed; 0 failed; strict isolation on; 7,264 ms.
- `PDF_ENCRYPTED_PERMISSIONS_ONLY` (INFO): PDF scanner decrypted with an empty user password and says contents were inspected.
- `CUSTOM_PDF_COVERAGE_LIMITED` (INFO): the custom PDF name-escape detector reports that encrypted strings and streams cannot be inspected by its own byte-level parsing.

**Code explanation:** `app/scanners/pdf.py` lines 155–163 use `PdfReader.decrypt("")` and continue walking the document graph. `app/engine/pdf_chains.py` likewise permits successful empty-password decryption. `app/scanners/custom/pdf_syntax.py` marks `/Encrypt` and deliberately does not decrypt object streams; `app/scanners/custom/pdf.py` reports `CUSTOM_PDF_COVERAGE_LIMITED` as INFO. The verdict logic in `app/decision/__init__.py` ignores INFO for escalation. These are different scanner capabilities, not logically contradictory reports.

**Unanswered:** Does the parsed/decrypted PDF graph provide equivalent coverage for every threat that the byte-level obfuscated-name detector is intended to catch? Does this specific fixture actually contain encrypted object streams or security-relevant opaque regions? Without evidence, do **not** call it a confirmed exploit.

## Evidence B: qpdf bad-data.pdf (validation-25)

- Pinned source: [qpdf fixture](https://github.com/qpdf/qpdf/blob/4eba95899886e851cc41d76886483b347612f2a8/qpdf/qtest/qpdf/bad-data.pdf)
- Pinned and scanned SHA-256: `919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057` (**matched**).
- Security Lab request: `8e8989c598a44208`, recorded `2026-11-13T17:49:43.953Z`.
- Observed: `SAFE`; `complete=true`; 5/5 applicable scanners completed; 0 failed; 0 findings; strict isolation on; 6,990.5 ms.
- **Verified from the pinned file's raw PDF syntax:** page object 3 references `/Contents 4 0 R`. Object 4 is a 48-byte stream with `/Filter /LZWDecode`. This is a **qpdf damaged-data test fixture**, but the observed Security Engine result does **not** establish whether that particular stream can be fully decoded or rendered. Do not infer a specific LZW decoding error without reproducing it using an independent bounded parser.
- **Code explanation:** `app/scanners/pdf.py` deliberately includes `/Contents` in `SKIP_KEYS` and focuses on document structure and actions. `app/engine/pdf_chains.py` reuses `SKIP_KEYS`. `app/scanners/custom/pdf_syntax.py` skips streams other than PDF object streams by design. Therefore successful **structural/security analysis is not a validation of all compressed page content**.

**Unanswered:** Does an independent parser reject, repair, or accept object 4's LZW data? If accepted, is the page content semantically valid? Would the actual FilesMagic converter encounter an error? `SAFE` is not sufficient evidence either way.

## Production gate requirements / remediation approach

### P0: Define and enforce the coverage contract

1. Add explicit coverage semantics separate from scanner execution: e.g. `scan_complete` (applicable scanners finished) versus `coverage_complete` / `coverage_issues[]` (threat-relevant areas analyzed), plus optional `conversion_input_validated` for streams and format features needed by the specific converter. Avoid changing the meaning of existing historical `complete` fields without a schema version.
2. **Fail closed for conversion authorization.** A file with unresolved required coverage must never receive conversion authorization merely because its highest finding is INFO and all scanners returned. Pending an equivalent-coverage proof, return `UNABLE_TO_SCAN` (or a separate explicit refusal state) for required missing coverage; retain higher severity threat findings when present. Do not label encryption or corruption `MALICIOUS` by default.
3. Log and expose the reason and scanner/module responsible, e.g. encrypted object stream not inspected, unsupported filter, failed stream decode, page-content stream not validated. Preserve strict isolation and resource limits.

### P1: Close the gaps with bounded checks

4. For empty-user-password encrypted PDFs, use the already authorized decrypted `pypdf` view **inside the isolated worker** to inspect or validate all object streams/parsed name objects required for C1's obfuscation checks. Only remove `CUSTOM_PDF_COVERAGE_LIMITED` if equivalent coverage is demonstrated with tests. Otherwise refuse conversion. Do not assume all encrypted PDFs are opaque.
5. Add bounded decode/integrity checks for **the compressed streams and formats the downstream converter will parse**, including page `/Contents` streams, rather than automatically treating skipped page data as validated. Enforce per-stream and cumulative decompression budgets; do not execute/render content or call external decoders in the security worker. Decoder errors/unsupported filters/partial reads must produce explicit unverified-coverage evidence and block conversion when that content is required.
6. Consider an independent, restricted parser check (e.g. qpdf `--check` under an **approved offline evaluation environment**, not arbitrary shelling out from the production web process) to characterize corpus cases. Preserve raw source, revision and hashes. Do not assert qpdf validates the downstream converter.

### P1: Reproducible acceptance tests

7. Add pinned regressions for the two exact SHA-256 values above, including an encrypted positive case with known active content hidden in a decryptable object stream and a matched benign encrypted control. Test both raw-byte and parsed-object coverage rather than only the verdict.
8. Add a valid LZW page-content control and a **proven malformed** LZW/page-content control with explicit expected decode outcomes. Validate that malformed/unreadable converter-relevant data cannot be authorized for conversion; ensure no incomplete scan silently returns SAFE.
9. Add differential parser tests for page streams, object streams, repaired cross-references, unsupported filters and resource exhaustion. Check that scan completion, coverage status, conversion authorization and messages agree.
10. Re-run the existing benign fixture corpus and the frozen benchmark **as a new, separately versioned experiment** to measure false-positive, latency and compatibility impact. Do not rewrite frozen evidence.

## Current release recommendation

- **Research staging:** continue safe, pinned benign and parser-stress testing on Render; preserve exact request IDs and hashes.
- **Production FilesMagic conversion:** **not approved** for Security Engine gating until the coverage contract and converter integration are designed and validated.
- **Severity terminology:** tracking priority **High / production gate blocker pending proof**, not a confirmed critical exploit; production risk is plausible because the downstream conversion parser may consume data the security scanner did not verify.
- **Do not repair during the ongoing external evaluation:** establish a baseline for the rest of the qpdf cases, implement fixes on a separate branch, and compare before/after.

Related freeze record: [engine-readiness-report.md](engine-readiness-report.md), which remains the authoritative November 9 research freeze and is **not** retroactively modified by these results.
