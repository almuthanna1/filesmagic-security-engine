# PDF coverage remediation — November 13, 2026

**Scope:** standalone research unified engine only. This report is a new post-freeze record; it does not alter the November 9 evidence, its totals, the reference scanners, or production FilesMagic.

## Inputs and verified causes

| Case | SHA-256 | Before | Verified cause | After |
| --- | --- | --- | --- | --- |
| qpdf `V4-aes.pdf` | `1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240` | `SAFE`, `complete=true`, custom INFO coverage note | pypdf decrypts the empty password and decodes 30 page streams. The raw file has `/Encrypt` but no `/ObjStm`; the old custom lexer reported all encryption as a C1 gap even when no encrypted object stream needed C1 inspection. | `SAFE`, `complete=true`, `coverage_complete=true` after bounded decrypted content inspection. |
| qpdf `bad-data.pdf` | `919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057` | `SAFE`, `complete=true`, no findings | Object 4 is a page `/Contents` stream declared as `/LZWDecode`; pypdf raises `PdfStreamError` (`LZW code 385 out of range with empty base at table index 267`). The structural scanners intentionally skipped page data. | `UNABLE_TO_SCAN`, `complete=true`, `coverage_complete=false`, `PDF_CONTENT_LZW_DECODE_FAILED`. |

Both source files were fetched from qpdf commit `4eba95899886e851cc41d76886483b347612f2a8` and hash-checked by the opt-in regression test. No assertion is made about rendering, universal PDF validity, conversion success, or malware detection.

## Change

The unified engine adds `pdf-integrity`. It resolves each page's direct or indirect `/Contents` value (including arrays), then uses pypdf in the existing isolated worker to decode only unfiltered streams and Flate, LZW, ASCIIHex, ASCII85, and RunLength filters. It does not render pages, evaluate JavaScript, access the network, or call external decoders.

Limits: 10,000 content streams, existing pypdf 20 MiB per-stream limits, 32 MiB total decoded content, existing object limit, 20-second CPU rlimit, 320 MiB worker memory default, and worker wall timeout. Unsupported filters, decode failure, unavailable password-protected content, parser repair, attachment incompleteness, and limits become bounded machine-readable coverage issues.

`complete` retains its historical meaning: every applicable scanner returned. New `coverage_complete` and `coverage_issues[]` state whether required coverage was established. A unified result with incomplete coverage is `UNABLE_TO_SCAN`, unless existing LOW/MEDIUM/HIGH/CRITICAL evidence already produces `SUSPICIOUS` or `MALICIOUS`; encryption and corruption are never automatically labelled malicious. Reference scanner behavior and rules are unchanged.

The C1 custom lexer no longer treats encryption alone as an incomplete C1 result. It still reports encrypted object streams it cannot inspect and retains the original escaped-name spelling as evidence where it does inspect tokens.

## Tests and measurements

- Fresh isolated Windows virtual environment installed pinned `requirements-dev.txt`, including `msoffcrypto-tool 6.0.0`.
- Baseline could not finish through the host's 30-second command window; after the implementation the same full backend suite was run in two partitions: **1,069 passed, 41 skipped** (the skips are Linux-only isolation tests on Windows), 33.9 seconds combined.
- Pinned qpdf regression test: **2 passed** in 0.48 seconds. New local PDF-integrity tests cover valid/malformed LZW, unsupported filter, encrypted accessible/unavailable content, total decoded-byte limit, and both exact qpdf hashes.
- Existing frozen API expectations, malicious/suspicious precedence, custom PDF tests, and frontend type/tests passed. Frontend: `tsc --noEmit` and 27 Node tests passed.

## Remaining limitations

This is intentionally not a full PDF validator. It does not validate drawing semantics, image/font/metadata streams, all PDF filters, cross-reference repair correctness, JavaScript execution, remote resources, attachments beyond existing attachment analysis, or the downstream FilesMagic converter. The Linux namespace/tunl0 tests require the Ubuntu CI environment described in `.github/workflows/ci.yml`; they were skipped on this Windows host and must pass in PR CI before merge. No deployment, production modification, or automatic merge was performed.
