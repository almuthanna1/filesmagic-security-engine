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

# After the false-positive fixes (commit `5b0e682`, 2026-11-08)

Unified engine only; the original four scanners are unchanged. Algorithms: `app/engine/correlate.py`
(module docstring), `app/engine/file_paths.py`, `app/engine/pdf_attachments.py`.

| Set | Original engine, non-SAFE | Unified, before | Unified, after |
|---|---|---|---|
| Development: 29 authored files (`after-local.json`) | 4 | 4 | **1** (docx-05, local template: LOW by design) |
| Held out: 4 government documents (`independent-after-local.json`) | 3 (IRS forms MALICIOUS) | 3 (SUSPICIOUS) | 3 (SUSPICIOUS, unchanged) |
| Synthetic: 16 inert cases (`../custom-engine-fp-fixes/`) | unchanged | - | no verdict changes |

Changed verdicts (unified): `docx-04` and `xlsx-04` SUSPICIOUS -> SAFE (every network-path target
is a picture or linked workbook on a local drive path); `pdf-07` SUSPICIOUS -> SAFE (the
attachment is an OpenDocument text without macros, scripts or links, and the PDF has no actions).
No added scanner failures or incomplete scans. Detection time rose on PDFs with many objects
(every object is now read and each attachment decoded): IRS forms about 58 -> 116 ms of a scan
of several seconds; elsewhere within run-to-run noise.

Staging (`staging-fp-fixes.json`, Render `5b0e682`, strict isolation, 12 tokens per window): the four
changed files, 5a, 5b, the four held-out documents, the UNC picture (6g) and a truncated PDF.
24/24 scans HTTP 200, `isolation_missing: []`, verdicts equal to the local results.

# Security review of the three superseding rules (2026-11-08)

A review of the only three rules that may lower an original finding. Each gap below was shown with
an inert input, fixed in the unified engine only, and pinned by a test in
`tests/test_false_positive_fixes.py` or `tests/test_file_paths.py` (25 of the new tests fail on the
code at `5b0e682`). The original four scanners are unchanged.

| Rule | Gap found | Fix |
|---|---|---|
| `ENGINE_PDF_ATTACHMENTS_VERIFIED` | Code was searched for as text in the raw XML bytes: another namespace prefix, UTF-16, `text:script`, `draw:applet`/`object-ole`/`floating-frame`, `office:binary-data` and `xml:base` all passed. `http(s)` was allowed on every element, so a remote `draw:image` (fetched on open) was "verified"; so was `./../x`. A NUL or bidi control in the file name (`plan.exe<NUL>.odt`) passed. | Every XML part is parsed (defusedxml, namespace-aware, any encoding); elements that run code or embed objects are rejected by local name in any namespace; `xlink:href` must name a part of the package, except `http`/`https`/`mailto` on a hyperlink (`a`), which opens only on a click and is counted in the evidence; any other attribute naming something outside the package is rejected; pictures must carry their format's signature; one ZIP from byte 0 to the end with no hidden members, duplicates or comment; names without control or formatting characters; decoding bounded at 100 attachments and 64 MB per PDF, XML reading at 16 MB per PDF; every `N G obj` header in the file must be one the cross-reference table points to. |
| `ENGINE_OFFICE_LOCAL_FILE_TARGETS` | Only the relationship *type* was checked: an `image` relationship to `file:///C:/…/calc.exe` referenced by a `w:hyperlink` (a click can start it) was superseded. The text claimed using the path "cannot send Windows credentials to a server". | Every element referencing the relationship must load it as data (`blip`/`imagedata`; `externalBook`/`absoluteUrl`/`relativeUrl`); unreferenced ones are not superseded. The text now says what is shown: the document does not direct Windows to a server its author chose; a drive or folder may still be network storage the opening machine maps. |
| `ENGINE_OFFICE_LOCAL_TEMPLATE` | Accepted when the strongest referencing element was `w:attachedTemplate`, whatever else referenced it. | Only `w:attachedTemplate` may reference it. Text states the same limit about mapped drives. |
| All three (`file_paths.py`) | `re.IGNORECASE` without `re.ASCII`: the Kelvin sign was a drive letter, `localhoſt` was `localhost`. | ASCII-only matching. |
| All three (`correlate.py`) | A superseding rule could lower a reference finding of any severity. | Each may lower only up to the severity it was validated on (MEDIUM, MEDIUM, LOW); a higher-rated finding stands. |

Re-run after the fixes (`review-local.json`, `independent-review-local.json`; the 16 synthetic
scenarios at 20 trials each):

| Set | Verdict changes | Finding changes |
|---|---|---|
| Development, 29 files | none (unified: docx-04, xlsx-04, pdf-07 stay SAFE; docx-05 SUSPICIOUS) | none |
| Held out, 4 files | none | IRS forms: `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` (LOW, merging the two LOW reference findings) becomes `ENGINE_PDF_ATTACHMENTS_INCOMPLETE` (INFO) with both reference findings kept: each form holds object 1032 twice (the linearized original at byte ~820 and a later incremental update), so not every attachment-bearing object is the one a reader uses |
| Synthetic, 16 cases | none | none (identical to `../custom-engine-fp-fixes/`, both engines, deterministic) |

Why the three corrections still hold: pdf-07's attachment, re-read under the stricter rules, has no
code elements, no references outside its own parts, and one hyperlink (`text:a` to
`https://www.niu.edu/`), which is passive and now listed. docx-04's picture is referenced only by
`a:blip`, xlsx-04's link only by `externalBook`/`absoluteUrl`/`relativeUrl`, both on drive paths that
name no host. The corrections now claim only that.

Staging (`staging-review.json`, Render `9111e5a`, strict isolation, 12 tokens per window, three
windows): the 12 files of the previous staging check plus six inert regression fixtures for the
gaps above (remote picture, prefixed and UTF-16 event listeners, NUL in the attachment name, an
object outside the cross-reference table, an image relationship used as a hyperlink). 36/36 scans
HTTP 200, `isolation_missing: []`, verdicts equal to the local results; the fixtures stay
SUSPICIOUS in both engines. Vercel was not redeployed (frontend unchanged, still `37737f5`).
