# C2PA Content Credentials accuracy: before/after evidence (`9882cbf` -> `e2eb2c7`)

Plan, predictions and corpus, committed before the change:
[`docs/c2pa-accuracy-preregistration.md`](../../c2pa-accuracy-preregistration.md) and
[`evaluation/c2pa_corpus.json`](../../../evaluation/c2pa_corpus.json) (`c467c97`). Change: `c873706`
(the verifier, `app/engine/c2pa.py`) and `e2eb2c7` (its limits per PDF). Baseline: `9882cbf`, the
build on staging. Harnesses: `evaluation/c2pa_accuracy.py`, `evaluation/c2pa_limits.py`.

    python -m evaluation.c2pa_accuracy --before <checkout of 9882cbf> --public <download dir> \
        --local <dev map> --local <held-out map> --trials 3 --out <dir>
    python -B -m evaluation.c2pa_limits            # worst cases, from a checkout

Files: `summary.md` / `summary.json` (sample IDs, rule IDs, counts and timings only) and the worst
cases at the limits, `limits-c873706.md` (1 trial) and `limits-e2eb2c7.md` (3 trials), with peak
memory: `limits-mem-c873706.md` (1 trial) and `limits-mem-e2eb2c7.md` (3 trials). Staging deployment
and its tests: `staging-e2eb2c7.md`, `staging-e2eb2c7.json`. The per-sample
findings (`results.json`, SHA-256 `97fc47b5...29991`) stay local: they quote private documents.
Windows 11, Python 3.14.3; each tree scanned by its own worker subprocess; 3 trials per scan, all
deterministic; both trees clean (`dirty: false`). Run 2026-11-11 17:21-17:52 UTC. Linux CI passed on
both commits (`e2eb2c7`: 1148 tests, 31 isolation tests).

## Sequence

1. `c873706`: verifier, harness, 51 synthetic cases, tests. Its evaluation run was stopped when the
   session ended, before it wrote any result; no held-out result was seen.
2. Measuring the worst case at the limits (pre-registration, section 2 point 1) at `c873706` showed
   work the limits did not cap (`limits-c873706.md`): the limits were per manifest store and a PDF
   may carry 100 attachments (100 stores of 100,000 CBOR items: 2.5 s); boxes were listed before
   they were counted; chunks of an indefinite-length string and JSON values were not counted
   (16 million empty chunks: 5.5 s, and about 1.5 GB of memory for a 17 KB PDF); JPEG fill bytes and
   PNG chunks were read one at a time. `c873706` was never deployed.
3. `e2eb2c7`: every limit counts all the stores of one PDF together, plus 100,000 JPEG markers and PNG
   chunks and 1 MiB of JSON; boxes are counted as they are read; fill bytes and image data are
   searched by regular expression. Each change only makes verification stricter. The new picture
   checks return exactly what the old ones did on 19,850 pictures (the dev JPEGs and seeded random
   mutations of them and of the synthetic pictures; dev files only).
4. The evaluation below, at `e2eb2c7`, the first and only run that produced held-out results.

## Predictions

| | Prediction | Result |
|---|---|---|
| P1 | Reference engine identical on every sample | **held**: 0 changes in 252 samples |
| P2 | D1 SUSPICIOUS -> SAFE through `ENGINE_PDF_ATTACHMENTS_VERIFIED`, evidence naming the manifest, its three assertions, the static SVG and the unvalidated signature; both reference LOWs kept raw | **held** (evidence quoted below) |
| P3 | Dev derived CD04-CD08: SUSPICIOUS -> SAFE, 5 of 5 | **held**: 5 of 5 |
| P4 | Held-out derived CH08-CH31: at least 20 of 24 SAFE, the rest SUSPICIOUS with a reason outside section 2 point 3; none MALICIOUS | **held**: 21 of 24 SAFE; CH29-CH31 SUSPICIOUS (thumbnail JPEG malformed, below); none MALICIOUS |
| P5 | CH01 stays SUSPICIOUS (predicted cause: an older revision, INCOMPLETE); if its inspection is complete and its manifest meets section 2, SAFE. CH02: the same if it carries a manifest. Neither MALICIOUS | **held through the conditional branch; the predicted cause was wrong**: CH01's inspection was complete and its 3 manifests met section 2, so SAFE. CH02 carries a manifest (2 manifests), SAFE |
| P6 | Controls (CD01-CD03, CH03-CH07) and every regression sample identical | **held**: 0 changes |
| P7 | Synthetic: `c2pa-benign` -> SAFE; every active, deceptive and malformed case at least SUSPICIOUS with its reason; the two `dangerous` cases MALICIOUS | **held**: 9/9 SAFE, 38/38 SUSPICIOUS, 2/2 MALICIOUS; C72 and C73 SUSPICIOUS |
| P8 | Attack strings: XSS and control characters SUSPICIOUS; SQL injection, 10,000 characters, punctuation SAFE | **held** for all 32 strings (below) |
| P9 | No HIGH/CRITICAL lost; no new MALICIOUS on a benign sample; deterministic | **held** |
| P10 | `pdf-chains` paired median: under 1 ms change without C2PA, under 20 ms increase with C2PA; worst case at the limits under 2 s | **held at `e2eb2c7`**: -0.003 ms (66 PDFs), +0.19 ms (114 PDFs), worst case 525 ms. **Failed at `c873706`** (5.5 s), which is why `e2eb2c7` exists |

## Which documents changed verdict, and why

57 samples, all in the unified engine, all SUSPICIOUS -> SAFE, each by the same mechanism: the one
LOW finding `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` became `ENGINE_PDF_ATTACHMENTS_VERIFIED` (INFO),
because every attachment was read completely and verified as a C2PA manifest store without active
content, and no action in the PDF runs a script, launches a file or opens an embedded document. The
two reference LOW findings it accounts for are kept verbatim as `raw` lines in
`ENGINE_CORRELATION`.

| Samples | Split | What they are |
|---|---|---|
| D1 | dev | the original APA report as exported (private) |
| CH01 | held-out | `adobe-20240110-single_manifest_store.pdf`, c2pa-org public test file: 3 manifests, no pictures |
| CH02 | held-out | c2pa-rs `express-signed.pdf` (Adobe Express): 2 manifests, no pictures |
| CH08-CH28 (21) | held-out | manifest stores of 20 Adobe (2022) and 1 Nikon public test JPEGs, embedded in a PDF the way D1 embeds its own |
| CD04-CD08 (5) | dev | the same, from c2pa-rs test files |
| C01-C09 (9) | dev | synthetic benign stores (CBOR, JPEG/PNG thumbnails, static SVG, JSON, salt and padding, `.c2pa` name, two stores, one next to an OpenDocument file) |
| 19 attack strings | dev | claim titles that are text without markup or control characters (P8) |

Nothing else changed: no reference verdict, no control, no regression sample, no HIGH finding.

### The original APA research report (D1)

Yes, it is now classified more precisely. Before: SUSPICIOUS, because its one attachment could not
be verified. After: SAFE, with this evidence:

> Content Credentials: a C2PA manifest store (Content Credentials) whose signature was not
> validated (24296 bytes): 1 manifest(s), no script, active markup or external reference; data in
> CBOR or JSON and 1 picture(s): c2pa.icon static SVG; assertions c2pa.icon, c2pa.actions.v2,
> c2pa.hash.data

So the warning no longer says "an attachment we cannot read"; the report says what the attachment
is (the export's Content Credentials), what it holds, and that nothing in the PDF opens it. It does
not say the credentials are authentic: the signature, certificate and hash binding were not checked.
The metadata-removed variant (D2) and the third variant (D3) were already SAFE and did not change.

## Benign documents that still warn (unified, after)

| Document | Verdict | Why | Assessment |
|---|---|---|---|
| CD03 c2pa-rs `basic-attachments.pdf` (dev control, no C2PA) | MALICIOUS before and after | reference `PDF_JAVASCRIPT_EXPLOIT_API` HIGH and an automatic document script (`ADBE::FileAttachmentsCompatibility`), next to two PNG attachments | **a false positive this change does not address** (not C2PA); kept, not hidden; a candidate for a separate study |
| CH29-CH31 Truepic test JPEGs (held-out derived) | SUSPICIOUS | each thumbnail (`c2pa.thumbnail.claim.jpeg`) has 2 zero bytes between its Exif segment and the next marker (DQT at byte 164), which baseline JPEG does not allow and libjpeg reports as "extraneous bytes" | justified by the pre-registered rule; accepting padding now would be tuning to held-out data |
| CH07 c2pa-rs `basic-password.pdf` | SUSPICIOUS | encrypted (`PDF_ENCRYPTED` MEDIUM) | justified: unchanged |
| IRS f1040, fw4, fw9 | SUSPICIOUS | automatic form JavaScript (MEDIUM) | justified by policy: unchanged |
| `docx-05-word-custom-template` | SUSPICIOUS | template on a drive path loaded on open (LOW) | deliberate: unchanged |

## False positives, false negatives, rates

| Split | Benign n | Unified MALICIOUS on benign (after) | Unified any warning, before -> after | Reference any warning |
|---|---|---|---|---|
| dev | 18 | 1 (CD03, unchanged) | 16 -> 1 | 16 |
| held-out | 31 | 0 (95% CI 0-11.0%) | 27 -> 4 (95% CI 5.1-28.9%) | 27 |
| regression | 90 | 0 (95% CI 0-4.1%) | 4 -> 4 | 8 |

False negatives: 0. All 38 constructed active, deceptive and malformed manifests stay at least
SUSPICIOUS, each naming the first item that failed (for example "c2pa.icon: markup with element
'script'"); the store that an automatic action exports (C70) or launches (C71) is MALICIOUS through
`ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT` HIGH; the 3 regression `dangerous` cases stay MALICIOUS.
The malicious controls are constructed and inert (no genuine malware was used or uploaded); no
false-negative rate is computed for them.

Attack strings (c2pa-attacks, 32): SUSPICIOUS: the 4 XSS strings (markup), 2 of 5 rendering strings
(backspace, vertical tab) and 7 of 12 special-character strings (NUL, SUB, DEL, ESC, backspace);
SAFE: carriage return, tab and escape sequences written as text, plain punctuation, the 10 SQL
injection strings and the 10,000-character string.

## Latency

Paired by sample, median of 3 trials each, `pdf-chains` time (the scanner the change touches):

| PDFs | n | paired median | range |
|---|---|---|---|
| without a C2PA manifest | 66 | -0.003 ms | -4.4 to +33.8 ms (largest on 7-8 MB private PDFs: noise, the code path is unchanged) |
| with a C2PA manifest | 114 | +0.19 ms | -1.3 to +34.3 ms (CH13-derived, 53.9 ms after) |

Wall time per scan is about 600 ms, mostly the fresh worker process (as in the previous study).
Worst cases at the limits (each a small PDF whose FlateDecode attachments decode to up to the 16 MiB
read budget), unified scan in-process:

| Case | `c873706` | `e2eb2c7` |
|---|---|---|
| indefinite text of 16 million empty chunks | 5,519 ms, verified | 50 ms, not verified (items) |
| 100 stores of 100,000 CBOR items | 2,510 ms | 113 ms (items) |
| 50 stores of 10,000 SVG elements | 1,556 ms | 108 ms |
| JPEG: 4 million empty COM segments | 1,575 ms | 79 ms, not verified (markers) |
| JPEG: 16 MiB of fill bytes | 1,324 ms | 328 ms |
| one superbox of 2 million empty boxes | 1,324 ms | 14 ms |
| JSON: 8 million values | 972 ms, verified | 18 ms, not verified (JSON size) |
| PNG: 1.4 million empty chunks | 764 ms | 64 ms, not verified (chunks) |
| JPEG: 16 MiB of image data that resembles markup (the regular-expression scan) | 502 ms | **525 ms (the worst case)** |

All 18 cases: `limits-*.md`.

## Departures from the pre-registration, and observations

- Limits per PDF instead of per store, and the new JPEG marker / PNG chunk and JSON-size limits
  (`e2eb2c7`, above): stricter than registered; decided from the worst-case measurement before any
  held-out result existed.
- Event handlers in text: registered as `on<letters>=`; implemented only after a space, quote or
  slash (or at the start), so a URL query such as `&online=1` is text. `<`-tags and `javascript:`
  are as registered.
- SVG values: registered as "no backslash, colon or `url()` other than `url(#id)`"; implemented as an
  allowlist of characters (letters, digits, space, `. , # % ( ) + -`) and of functions (`rgb`,
  `matrix`, `translate`, `url(#id)` and similar), which is stricter.
- Text check: `str.isprintable()` is the fast path; only text that fails it is examined character by
  character for control and formatting characters (tab, LF and CR allowed).
- Evidence order: the caveat "whose signature was not validated" comes first, because evidence lines
  are cut at 300 characters.
- Observed, not changed (fail safe, pre-existing): `correlate.finding` keeps at most 50 evidence
  items, so a PDF with more than 48 attachments loses the "accounts for" lines and the reference LOW
  findings stand even when every attachment is verified.

## What this does not show

- Authenticity: no signature, certificate, hash binding or trust list was checked; "verified" means
  "no active content in a structure read completely".
- Real C2PA PDFs: only three (D1, CH01, CH02). The 26 derived samples are real manifest stores from
  public JPEGs, embedded by the harness the way D1 embeds its own; they test the manifest reader,
  not other producers' PDF structures.
- Genuine malicious C2PA files: none is known publicly, and none was sought; the malicious and
  deceptive controls are constructed.
- Linux timings: latency was measured on Windows; Linux CI ran the tests only. Staging (Linux, free
  instance) timings and the limit cases under the worker's 256 MB memory limit: `staging-e2eb2c7.md`.
