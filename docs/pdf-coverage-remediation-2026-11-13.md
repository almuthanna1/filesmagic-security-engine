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

`complete` retains its historical meaning: every applicable scanner returned. New `coverage_complete` and `coverage_issues[]` state whether required coverage was established; any failed applicable unified scanner produces `SCANNER_ANALYSIS_FAILED` (or the more specific integrity failure) and makes coverage incomplete. A unified result with incomplete coverage is `UNABLE_TO_SCAN`, unless existing LOW/MEDIUM/HIGH/CRITICAL evidence already produces `SUSPICIOUS` or `MALICIOUS`; encryption and corruption are never automatically labelled malicious. Reference scanner behavior and rules are unchanged.

The C1 custom lexer no longer treats encryption alone as an incomplete C1 result. It still reports encrypted object streams it cannot inspect and retains the original escaped-name spelling as evidence where it does inspect tokens.

## Tests and measurements

- Fresh isolated Windows virtual environment installed pinned `requirements-dev.txt`, including `msoffcrypto-tool 6.0.0`.
- Baseline could not finish through the host's 30-second command window; after the implementation the same full backend suite was run in two partitions: **1,069 passed, 41 skipped** (the skips are Linux-only isolation tests on Windows), 33.9 seconds combined.
- Pinned qpdf regression test: **2 passed** in 0.48 seconds. New local PDF-integrity tests cover valid/malformed LZW, unsupported filter, encrypted accessible/unavailable content, total decoded-byte limit, and both exact qpdf hashes.
- Final API-path replay through the real child worker is recorded in [`evidence/pdf-coverage-remediation-2026-11-13/api-worker-results.json`](evidence/pdf-coverage-remediation-2026-11-13/api-worker-results.json): `V4-aes.pdf` was `SAFE`, complete and coverage-complete; `bad-data.pdf` was `UNABLE_TO_SCAN`, complete but coverage-incomplete with `PDF_CONTENT_LZW_DECODE_FAILED`.
- Existing frozen API expectations, malicious/suspicious precedence, custom PDF tests, and frontend type/tests passed. Frontend: `tsc --noEmit` and 27 Node tests passed.
- Subsequent final PR #21 review reported **1,073 backend tests passed** on Windows with 41 Linux-only skips; the three GitHub checks (Linux backend/isolation, Docker non-root image and frontend checks) passed on head `38c2922` before research-only merge `840a300c`.

## Remaining limitations

This is intentionally not a full PDF validator. It does not validate drawing semantics, image/font/metadata streams, all PDF filters, cross-reference repair correctness, JavaScript execution, remote resources, attachments beyond existing attachment analysis, or the downstream FilesMagic converter. Linux namespace/tunl0 tests were skipped on the Windows development host, but the PR's Linux backend/isolation, Docker and frontend CI checks passed before merge. The isolated research Render and Vercel staging services were subsequently deployed; production FilesMagic and its conversion backend were not changed.

## Hosted follow-up: manual Security Lab rescans (November 14, 2026)

**Status: observed and recorded, post-freeze.** The user manually scanned the original, upstream-pinned files in the deployed *research-only* Security Lab. These are saved-history transcriptions, not raw JSON API responses. Machine-readable case records, scanner durations, findings, SHA-256 values and reported isolation flags are preserved in [staging-840a300c-2026-11-14.json](evidence/pdf-coverage-remediation-2026-11-13/staging-840a300c-2026-11-14.json). This does not revise the November 9 freeze.

**Version and environment:** Unified engine 0.2.0 at merge commit [`840a300c`](https://github.com/almuthanna1/filesmagic-security-engine/commit/840a300c1edf4682cbd4ba7ecc7f183ba281983e); pypdf 6.19.0 and YARA-X 1.21.0; Render research-only service `filesmagic-security-engine-staging`, deployment `dep-dbrsv0ei0phs73benb70`; Vercel research-only Lab `filesmagic-security-lab-staging`, deployment `dpl_62M8ScJXQmMSdWqxZZWawMgG5TRU`. PR [#21](https://github.com/almuthanna1/filesmagic-security-engine/pull/21) merged into `feature/custom-unified-engine-nov18`; no production FilesMagic service was changed.

| Pinned fixture | SHA-256 | Baseline Nov 13 | Hosted Nov 14 | Hosted time |
| --- | --- | --- | --- | ---: |
| `V4-aes.pdf` (`validation-24`) | `1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240` | SAFE with `CUSTOM_PDF_COVERAGE_LIMITED` (INFO); 7,264 ms | SAFE; the custom gap warning is absent; one `PDF_ENCRYPTED_PERMISSIONS_ONLY` (INFO) remains | 7,289.8 ms |
| `bad-data.pdf` (`validation-25`) | `919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057` | SAFE, zero findings; 6,990.5 ms | UNABLE_TO_SCAN; `ENGINE_PDF_COVERAGE_INCOMPLETE` (INFO) cites `PDF_CONTENT_LZW_DECODE_FAILED` | 6,044.7 ms |

The Security Lab reported both input SHA-256 values **matched** the pinned qpdf revision `4eba95899886e851cc41d76886483b347612f2a8`. Recorded scan times were `2026-11-14T03:21:09.705Z` and `2026-11-14T03:21:49.299Z`; respective request IDs were **`91d02883c3d8406f`** and **`b4e41e363e8b4afe`**. Both were identified as PDF, had `complete=true`, and reported **6 of 10 scanners completed**, 4 not applicable, **0 failed**. In both cases `pdf-integrity` completed. No additional malware-related finding was claimed.

**Coverage contract:** `complete=true` confirms that applicable scanners returned, not that every required document region was analyzable. The hosted bad-data verdict and PDF-integrity finding specifically demonstrate the new fail-closed outcome when LZW page-content decoding fails. The copied **saved history does not explicitly print `coverage_complete` or `coverage_issues`**, so the two fields must not be represented as directly exported hosted measurements. The earlier [Windows API-worker replay](evidence/pdf-coverage-remediation-2026-11-13/api-worker-results.json) explicitly records `coverage_complete=true` for the encrypted control and `coverage_complete=false` with `PDF_CONTENT_LZW_DECODE_FAILED` for damaged data. The hosted findings and verdicts are consistent with those values, but any final machine-readable hosted coverage claim requires retaining the raw hosted API response.

**Isolation, as reported by the Linux worker:** strict isolation required; no missing required controls; `process`, `network_namespace`, `network_verified`, `audit_hook`, `rlimits` and `capabilities_dropped` were true in both histories. `net_loopback_only=false` was recorded alongside `net_fallback_tunnel_inert=true`, `net_interfaces_safe=true`, and both IPv4/IPv6 unreachable/no-route checks true. This is not a missing isolation control or an independent external kernel probe.

**Interpretation and limits:** The two targeted regressions behaved as intended in the hosted environment. The AES example was decryptable with an empty user password and did not contain an encrypted `/ObjStm`; encryption alone was not a demonstrated gap in that file. The damaged file's page `/Contents` LZW stream failed a bounded decoder and is no longer silently classified SAFE. One scan of each file cannot establish a latency improvement: the hosted wall times differ from the earlier single runs, and free-instance scheduling/worker start-up varies. These results do not prove full PDF validity, general malware-detection accuracy, converter safety, or closure of separate unsupported-format and repaired-PDF issues. The production conversion gate remains out of scope.
