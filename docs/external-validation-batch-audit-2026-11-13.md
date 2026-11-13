# November 13 external validation: 32-case catalog audit

**Evidence status:** user-provided export of the Security Lab's **Copy recorded results** action on 2026-11-13. **Post-freeze supplementary evaluation**, independent from the November 9 frozen benchmark `eda2a08`. It is **not all historical scans**; the export covers the catalog `validation-01` to `validation-32` only.

**Engine:** unified 0.2.0; the 30 saved results report backend commit `ccdb462065fcf3140e5a2295f3754f3c19324ab0`. The conversion engine is **not integrated** and production readiness is **not established**.

## Audit counts

| Measure | Count |
|---|---:|
| External catalog cases | 32 |
| Entries in uploaded export | 31 |
| Actual saved scan-history reports | 30 |
| Saved `SAFE` reports | 21 |
| Saved `SUSPICIOUS` reports | 8 |
| Saved `UNABLE_TO_SCAN` reports | 1 |
| Manual-only SAFE assertion, no saved scan evidence | 1 (validation-03) |
| Not present in export | 1 (validation-32) |
| Saved scans with `complete=true` | 29/30 |
| Saved scans with missing required isolation controls | 0/30 reported |
| Saved scans with individual isolation-control detail absent from old browser history | 7 |
| Saved scans with failed scanner(s) | 1/30 (2 scanner failures in validation-26) |

Median total time of the 30 saved scans: **6,882.9 ms** (range 6,360.3–8,208.0 ms). Median of sums of individual scanner timing: **94.8 ms**. Most measured wall-clock time is outside the individual scanner timing reports, but startup, isolation, and networking have not been separately instrumented.

| Source | Actual SAFE | Actual SUSPICIOUS | Actual UNABLE_TO_SCAN | Manual only | Missing |
|---|---:|---:|---:|---:|---:|
| Apache POI (12 cases) | 11 | 0 | 0 | 1 | 0 |
| veraPDF (7) | 0 | 7 | 0 | 0 | 0 |
| qpdf (9) | 7 | 1 | 1 | 0 | 0 |
| oletools (2) | 2 | 0 | 0 | 0 | 0 |
| EICAR (2) | 1 | 0 | 0 | 0 | 1 |
| **Total** | **21** | **8** | **1** | **1** | **1** |

## High-priority production gate concerns

### A. `validation-27` bad-direct-root.pdf: unknown format returns SAFE

Pinned source: qpdf `4eba95899886e851cc41d76886483b347612f2a8`; SHA-256 `0d7549c02c38717627deb10d1155c1b513d35036208e77d687597c77d04dc3b4`; request `53d3daeacb5f4f51`.

Result: `detected_format=unknown`, `SAFE`, `complete=true`; only 2/9 scanners (YARA-X and yara-x-engine) completed, and seven including the PDF scanner were not applicable. The pinned file is 284 bytes and begins with **`UPDF-1`**, not `%PDF-`. It is a malformed format fixture, not a PDF content scan.

**Policy defect to address:** an unknown/unsupported file type must not be authorized for conversion on the strength of two clean generic signature scans. Distinguish `scanner execution complete` from `document supported and sufficiently inspected`. Reject/return `UNABLE_TO_SCAN` for unsupported conversion inputs unless an explicitly documented format allowlist and mandatory inspection contract both pass. A SAFE verdict here is not evidence of a demonstrated malware exploit, but is a strong fail-open **authorization risk**.

### B. `validation-28` append-xref-loop.pdf: incomplete repaired PDF analysis returns SAFE

Pinned SHA-256 `7c67daccc433f574fbaf815d0d376cc79f40f95082ef1b231af436e9f7d27091`; request `87e9c571bdb04065`.

Result: `SAFE`, `complete=true`, five applicable scanners completed, but **44 parser repairs** and three INFO findings: `PDF_STRUCTURE_REPAIRED`, `ENGINE_PDF_CHAINS_REPAIRED`, `ENGINE_PDF_ATTACHMENTS_INCOMPLETE`. This demonstrates that successful scanner return does not prove complete attachment analysis. Required coverage limitations must block conversion authorization rather than silently pass as INFO.

### C. `validation-24` V4-aes.pdf: custom encrypted-object coverage limitation

Pinned SHA-256 `1d8a812844b8d8c7ba085a627eb3b7ab52aa651c6143ca07315084220a113240`; request `9db6839ce4584ccb`.

Result: `SAFE` and `complete=true`; pypdf reported successful empty-password decryption (`PDF_ENCRYPTED_PERMISSIONS_ONLY`), but the custom syntax scanner reported `CUSTOM_PDF_COVERAGE_LIMITED`: encrypted strings/streams were not fully inspected by that scanner. Need proof that another scanner provides equivalent threat coverage, or fail-closed conversion authorization. No malicious payload or exploit was demonstrated.

### D. `validation-25` bad-data.pdf: skipped compressed page stream

Pinned SHA-256 `919998d65cecd40f1c33cf56853a517acc0e18f438fcc098f4c17a086c875057`; request `8e8989c598a44208`.

Result: `SAFE`, zero findings, five applicable scanners completed. The pinned damaged-data fixture contains an `/LZWDecode` page `/Contents` stream; the security structural scans exclude ordinary page content. Without bounded independent decoding, we **cannot establish** whether this specific stream is corrupt or whether a conversion parser would accept it. Require converter-relevant, resource-bounded stream validation and explicit partial-coverage signalling.

### E. Positive malformed-input fail-closed control: `validation-26` bad-xref.pdf

Pinned SHA-256 `5895dfedf978f600b12e29643617dbb111869b60526d957878e349571e1467d1`; request `5e37b6f6e3ae45cd`.

Result: `UNABLE_TO_SCAN`, `complete=false`, 3 completed and 2 failed applicable scanners (PDF and pdf-chains). Both reported `malformed_input: PdfReadError: Could not read Null object`. This is **one observed correct fail-closed path**, not general proof that malformed inputs always fail closed.

## Policy/compatibility findings

All **8 SUSPICIOUS** reports are `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` (LOW) with correlation evidence: veraPDF `validation-13`–`19` and qpdf `validation-23`. The examples include `.txt`, `.csv`, and `.xml` attachments that the restricted OpenDocument verifier cannot verify as code-free. These are potential false positives pending **independent attachment-content validation**, not confirmed malware-negative labels. veraPDF PASS/FAIL indicates PDF/A conformance, not a malware ground truth.

Apache POI `bar-chart.pptx` also produced `ENGINE_OFFICE_ACTIVATION_UNDETERMINED` (INFO) for a chart pointing at an embedded `.xlsx`. The oletools `harmless-clean.docm` produced `CUSTOM_OFFICE_MACRO_CAPABLE_DECLARATION` (INFO), identifying a macro-capable container with zero macro parts.

The EICAR `eicar.com.txt` 68-byte inert control, hash `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`, returned `SAFE` with zero YARA matches. The current rules did not flag that reference test string in this run; do not interpret this as a measurable real-malware false-negative rate. `eicar.com.zip` is **not in the export**, so its verdict is unknown.

## Evidence limitations and closure checklist

- **Validation-03:** `EmptyDocumentWithHeaderFooter.docx` is a manually selected SAFE observation with no source hash, engine commit, isolation status or findings. Retrieve or repeat the scan for a history-backed record.
- **Validation-32:** `eicar.com.zip` is missing, including any rejection or upload error. Capture a full scan result or explicitly label the failure.
- Every saved scan reports strict isolation and zero missing required controls, **but** detailed flags are absent from older cases 01 and 04–09. Do not invent missing flags.
- Only the pinned, hash-checked hosted fixtures provide source-level byte-fingerprint assurance in the recorded report; ordinary benign candidates have filename/history association without independently verified upstream hashes.
- These cases are third-party regression fixtures, not a representative statistically labelled set. Do not compute global false-positive or detection rates, or merge them into frozen `eda2a08` denominators.
- **Do not change the frozen Nov 9 evaluation.** Any subsequent remediation and rerun requires its own source commit, ruleset fingerprint, ground truth and latency record.
- Before conversion integration, define `format supported`, `scan complete`, `coverage complete` and `conversion authorized` separately. Block authorization on unresolved mandatory coverage, unexpected format, parser repair/incomplete evidence, or failed scan. Keep actual HIGH/CRITICAL evidence dominant when detected.
- No genuine malware may be sent to the hosted Render research scanner without separate institutional/provider authorization.

**Decision:** This 32-case external batch is **30/32 backed by saved scan history**, **one manual-only**, **one absent**. It exposed additional specific fail-closed policy blockers; the research Security Engine is **not yet approved** as a gate for production FilesMagic conversion.

Related: [external-pdf-coverage-findings-2026-11-13.md](external-pdf-coverage-findings-2026-11-13.md) and remediation issue [#14](https://github.com/almuthanna1/filesmagic-security-engine/issues/14).
