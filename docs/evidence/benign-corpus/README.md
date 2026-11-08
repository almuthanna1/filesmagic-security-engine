# Real-world benign validation: staging, 2026-11-08

| Item | Value |
|---|---|
| Corpus | `evaluation/benign_corpus/` at `4855530`: 29 known-benign files (8 PDF, 7 DOCX, 7 XLSX, 7 PPTX) by Word, Excel, PowerPoint 16, LibreOffice, Edge |
| Engine | Render staging, commit `7b4f838`, strict isolation required, `SECURITY_ENGINE_RESEARCH_ENGINES=1` |
| Lab | Vercel staging, commit `37737f5` (cold-start health retries) |
| Path | 12 files through the Lab UI (Compare both): `staging-ui-summaries.json`. 17 through the same Lab token route and engine `/scan` over HTTP, after the DevTools browser server failed: `staging-http-{0,1,2}.json` |
| Token limit | unchanged (12 per 15 min); 6 comparisons per window |
| Internal baseline | `local-windows.json`: same files, both engines, real worker on Windows (no isolation) |
| Combined | `staging-combined.json` |

## Results (29 files x 2 engines)

| | Result |
|---|---|
| Scans completed (HTTP 200, all applicable scanners) | 58 / 58; no UNABLE_TO_SCAN, no failed scanner |
| Strict isolation | `isolation_missing: []` on all 58 |
| Integrity | each response's SHA-256 = the manifest's; requested engine = responding engine; commit `7b4f838` |
| Reference vs unified verdict | agree on 29 / 29 |
| Staging vs local baseline | same verdicts on 29 / 29 |
| Correct negatives (SAFE) | 25 / 29 files, both engines |
| False positives (SUSPICIOUS on known-benign) | 4 / 29 files, both engines: see below |
| Whole-scan time, staging (median, range) | reference 6620 ms (5602-7488), unified 6764 ms (6048-7472) |
| Detection work, local (median sum of scanner times) | reference 6.1 ms, unified 7.7 ms |

The whole-scan time is the isolated worker's start-up on Render's Free instance, not detection:
detection is under 10 ms. One scan per file per engine: the difference between engines is not a
measurement.

## False positives, and why

| File | Feature (benign) | Rule | Cause |
|---|---|---|---|
| `docx-04-word-linked-picture` | picture inserted with "Link to File" | `OFFICE_EXTERNAL_NETWORK_PATH` MEDIUM | `office.external_relationship` treats every `file:` target as a network path; the target is `file:///C:\tmp\fm-benign\chart.png`, a local drive path. Only UNC (`\\host\share`) or `file://host/...` can reach a server and leak credentials. |
| `xlsx-04-excel-external-workbook-link` | formula referencing another workbook | `OFFICE_EXTERNAL_NETWORK_PATH` MEDIUM | same: Excel stores the link three ways (relative, `/tmp/...`, `file:///C:\...`); the `file:///C:` one triggers it |
| `docx-05-word-custom-template` | document created from a custom `.dotx` | `OFFICE_EXTERNAL_AUTOLOAD` MEDIUM; unified adds `ENGINE_OFFICE_EXTERNAL_ON_OPEN` MEDIUM | `attachedTemplate` is an auto-load relationship and is flagged wherever it points; template injection needs a remote template, this one is a local file |
| `pdf-07-libreoffice-hybrid` | LibreOffice "hybrid PDF" (the editable ODF embedded) | `PDF_EMBEDDED_FILE` LOW (pdf scanner and YARA-X) | any non-executable attachment is LOW, and LOW aggregates to SUSPICIOUS |

## Other issues found

1. Correlation notes on Office files (`ENGINE_CORRELATION`, INFO) are attributed to scanner
   `pdf-chains` and category `pdf-action-chain`: `correlate.finding()` defaults to the PDF chain
   scanner's name. Labelling only; no verdict changes.
2. Unified findings duplicate for one cause: `OFFICE_EXTERNAL_AUTOLOAD` and
   `ENGINE_OFFICE_EXTERNAL_ON_OPEN` for the same relationship; `PDF_EMBEDDED_FILE` from two scanners.
3. A hybrid PDF is also a valid ZIP (`zipfile.is_zipfile` is true). The engine routes it as a PDF
   (`detect_format` checks `%PDF-` first) and the Office scanners are not applied to the embedded
   ODF. The attachment's contents are not analysed; only its name and MIME type, which the file's
   author sets.
4. Corpus building: Office's "remove personal information" did not reach the workbook embedded
   behind a PowerPoint chart (fixed in `build.ps1`). Not an engine issue, but relevant to anyone
   sharing Office files.

## Limits

- Every file here is known-benign: this measures false positives only, not detection.
- 29 files from one machine and two producer families; neither corpus size nor variety supports
  rates beyond this corpus.
- SAFE means no known indicator was found. It is a correct negative here because the ground truth is
  known; for a file of unknown origin it would not show the file is harmless.
