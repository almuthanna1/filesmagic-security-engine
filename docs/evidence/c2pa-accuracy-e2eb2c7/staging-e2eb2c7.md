# Staging deployment of the C2PA accuracy change (`e2eb2c7`)

Approved by the user for the Render staging service `srv-dbelc2jrjlhs7382nv5g` only. Production
FilesMagic, the frozen release (`2d586f6`, tag `custom-engine-freeze-2026-11-09`) and the Vercel Lab
were not changed. No malware was uploaded: only the three APA report variants (private; hashes
below) and inert synthetic fixtures built by `evaluation/c2pa_accuracy.py`, `evaluation/pdf_accuracy.py`,
`evaluation/cases.py` and `evaluation/c2pa_limits.py`.

## Before deploying

| Check | Result |
|---|---|
| 1. Code identity | Deployed `e2eb2c70a61a...`, the commit the evaluation and the limit measurements ran on. The later commit `3f786cd` (head of `origin/feature/unified-c2pa-accuracy`) adds only `docs/` and `evaluation/`; `app/`, `Dockerfile`, `requirements.txt`, `render.yaml` and `.github/` are identical. `git diff 9882cbf e2eb2c7 -- app`: `app/engine/c2pa.py` (new, 400 lines), `app/engine/correlate.py` (+14/-9), `app/engine/pdf_attachments.py` (+29/-11); nothing else |
| 2. Linux CI | run 43067243372 on `e2eb2c7`: backend (Linux, non-root) 1148 passed, tunl0 isolation rerun 31 passed, Docker image, Lab build; run 43087769795 on `3f786cd`: success |
| 3. Aggregate limits | One verifier call site (`pdf_attachments.py`), one attachment inspection per scan (`pdf_chains.py`), one shared budget per PDF (`Counter` passed to every `c2pa.verify`): 10,000 boxes, 100,000 CBOR/JSON items (string chunks counted), 1 MiB text, 1 MiB JSON source, 10,000 SVG elements, 100,000 JPEG markers and PNG chunks, all summed over every attachment and nested store of the PDF; nesting 8 JUMBF / 64 CBOR levels per store; 16 MiB read budget per PDF; PDF stream decoding 20 MiB per stream and 64 MiB per PDF; nothing inside JUMBF is decompressed. Time: the worker's 20 s CPU limit and 30 s timeout; memory: the worker's `RLIMIT_DATA` (256 MB on staging) |
| 4. The old resource-exhaustion case | 16 million empty indefinite-length CBOR chunks in a 17,805-byte PDF. `c873706` (never deployed): 5,080 ms, peak 1,996 MiB working set / 2,006 MiB private, verified. `e2eb2c7`: 40-56 ms, peak 135 MiB / 122 MiB (3 trials; 68 MiB of it the warm process), not verified ("more than 100000 CBOR or JSON items"). Highest peak of all 19 limit cases at `e2eb2c7`: 150 / 133 MiB (`limits-mem-e2eb2c7.md`). Windows, in-process, `evaluation/c2pa_limits.py` |
| 5. Original engine; HIGH/CRITICAL | `git diff 2d586f6 e2eb2c7` and `git diff 9882cbf e2eb2c7` on `app/scanners`, `app/rules`, `app/decision`, `app/worker.py`, `app/main.py`, `app/auth.py`, `app/models.py`: empty. The verified-attachment rule supersedes only up to LOW (`SUPERSEDING` in `correlate.py`), only the two attachment rules (`pdf:PDF_EMBEDDED_FILE`, `yara-x:PDF_Embedded_File`), and only through whole-line "accounts for" evidence; the forged-name test removed no HIGH; 368 guard and engine tests passed locally |
| 6. Rollback target | `dep-dbps71gn74is738thlo0`, commit `9882cbf15e4681d16dc9d39ac1701f109db00b0e`, live 2026-11-11T01:23:49Z until this deploy; free plan, Docker, auto-deploy off, service branch `feature/custom-unified-engine-nov18` (unchanged) |

## Deployment

`render deploys create srv-dbelc2jrjlhs7382nv5g --commit e2eb2c70a61a0b2855b36a07282bb35d4da7b08f --wait`:
`dep-dbqc9tegekts7383m380`, created 2026-11-11T19:41:41Z, live 19:42:16Z (Docker layers cached except
`COPY app`). `/health` afterwards (3 checks, 0.13-0.21 s): `commit e2eb2c70a61a0b2855b36a07282bb35d4da7b08f`,
`engines [reference, unified]`, `default_engine reference`, `scanners_registered 4`, `scanners_ready 4`,
`auth_configured true`. The previous deploy is deactivated, not deleted. The Lab showed "This API
accepts both engines (commit e2eb2c70a61a)".

## The three APA variants (Lab, Compare Both)

| | SHA-256 (prefix) | Original engine | Unified engine | Same as local `e2eb2c7`? |
|---|---|---|---|---|
| D1 original | `a851ee59` | SUSPICIOUS: `PDF_Embedded_File` LOW (yara-x), `PDF_EMBEDDED_FILE` LOW (pdf) | **SAFE**: `ENGINE_PDF_ATTACHMENTS_VERIFIED` INFO (was SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` LOW, at `9882cbf`) | yes |
| D2 metadata removed | `36cba588` | SUSPICIOUS: `PDF_Embedded_File` LOW | SAFE: `ENGINE_PDF_NO_ATTACHMENTS` INFO (unchanged from `9882cbf`) | yes |
| D3 corrected | `1f35e349` | SAFE, no findings | SAFE, no findings | yes |

D1's unified evidence, as the Lab shows it:

> Content Credentials: a C2PA manifest store (Content Credentials) whose signature was not validated
> (24296 bytes): 1 manifest(s), no script, active markup or external reference; data in CBOR or JSON
> and 1 picture(s): c2pa.icon static SVG; assertions c2pa.icon, c2pa.actions.v2, c2pa.hash.data;
> accounts for pdf:PDF_EMBEDDED_FILE; accounts for yara-x:PDF_Embedded_File

and the finding's description ends "This shows what the attachments do not contain, not that they
are harmless or authentic." Both original LOW findings are kept verbatim in the correlation evidence
("raw yara-x:PDF_Embedded_File LOW: PDF carries an embedded file attachment.", "raw
pdf:PDF_EMBEDDED_FILE LOW: PDF carries 1 embedded file(s) (e.g. 'Content Credentials').") and listed
as "Superseded by correlation". All six scans: strict isolation required, `isolation_missing []`,
every applicable scanner completed (original 3 of 4, unified 5 of 9; the rest not applicable to a
PDF). Whole scan (worker start-up included), original -> unified: D1 6473 -> 6867 ms, D2 6649 ->
6811 ms, D3 6043 -> 6791 ms. Request IDs: D1 `23dd650014e348a4` / `2f39973622254f94`, D2
`d10fbd28ea134531` / `ef7f0bd3b17c406e`, D3 `3d07e96b3dd74f1a` / `b50460a96c184b1d`.

## HTTP tests (Lab token -> engine `/scan`, as the browser does)

61 scans and 4 failure checks, 2026-11-11 19:48-21:06 UTC, at the Lab's limit of 12 tokens per 15
minutes. Each scan was compared with the local result of `e2eb2c7` on the same bytes: verdict,
non-INFO rules and scanner statuses identical (the synthetic and regression cases against the local
evaluation run, `results.json` SHA-256 `97fc47b5...29991`; the limit PDFs against an in-process scan
of the same checkout; `corrupt-truncated-pdf` by verdict only), plus engine identity, scanner list,
commit, uploaded hash, CORS (`Access-Control-Allow-Origin` = the Lab), complete analysis and
`isolation_missing []`. The run stops at the first difference. **65 of 65 checks passed**, no client
network errors. Raw results: `staging-e2eb2c7.json`.

### Resource cases (test 7)

The 19 worst cases of `evaluation/c2pa_limits.py` (each a small PDF whose FlateDecode attachments
decode to up to the 16 MiB read budget), unified engine. Local columns: Windows 11, in-process,
`limits-mem-e2eb2c7.md` (3 trials).

| # | case | PDF bytes | staging verdict, rule | staging whole scan (ms) | staging pdf-chains (ms) | local unified scan (ms) | local peak MiB (working set / private) | reason not verified |
|---|---|---|---|---|---|---|---|---|
| 06 | CBOR: indefinite text of 16 million empty chunks | 17,805 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 7,155 | 806 | 56 | 135 / 122 | c2pa.test: more than 100000 CBOR or JSON items in the manifest stores of this file |
| 19 | all limits at once: 7 stores | 38,569 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 15,480 | 9,097 | 574 | 133 / 115 |  |
| 01 | boxes: 10,000 in one store | 1,594 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 6,425 | 93 | 5 | 69 / 51 |  |
| 02 | boxes: one superbox of 2 million empty boxes | 25,928 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 7,208 | 302 | 15 | 134 / 120 | more than 10000 boxes in the manifest stores of this file |
| 03 | boxes: 100 stores of 10,000 | 109,269 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 7,108 | 399 | 46 | 86 / 68 | more than 10000 boxes in the manifest stores of this file |
| 04 | CBOR: 100,000 items in one store | 1,573 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 7,024 | 402 | 33 | 68 / 50 |  |
| 05 | CBOR: 100 stores of 100,000 items | 107,169 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 8,180 | 909 | 78 | 89 / 71 | c2pa.test: more than 100000 CBOR or JSON items in the manifest stores of this file |
| 07 | CBOR: nesting 64 deep | 1,355 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 6,636 | 2 | 9 | 68 / 50 |  |
| 08 | JSON: 8 million values in one box | 17,814 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 6,760 | 300 | 21 | 132 / 118 | c2pa.test: more than 1048576 bytes of JSON in the manifest stores of this file |
| 09 | text: 1 MiB in one string | 2,493 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 6,945 | 396 | 31 | 72 / 55 |  |
| 10 | text: 16 stores of 1 MiB | 32,248 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 7,097 | 798 | 49 | 117 / 100 | more than 1048576 characters of text in the manifest stores of this file |
| 11 | SVG: 10,000 elements, 1 MiB of values | 5,528 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 7,370 | 1,101 | 163 | 79 / 61 |  |
| 12 | SVG: 50 stores of 10,000 elements | 114,119 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 7,595 | 1,111 | 113 | 150 / 133 | c2pa.thumbnail.claim: markup with more than 10000 elements in the manifest stores of this  |
| 13 | JPEG: 16 MiB of fill bytes | 17,893 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 10,398 | 4,207 | 308 | 132 / 118 |  |
| 14 | JPEG: 8 million stuffed FF00 pairs | 17,900 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 11,202 | 5,098 | 381 | 131 / 117 |  |
| 15 | JPEG: 4 million empty COM segments | 17,908 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 7,702 | 899 | 76 | 133 / 118 | c2pa.thumbnail.claim: JPEG with more than 100000 markers and chunks in the pictures of thi |
| 16 | JPEG: 16 MiB of entropy data like markup | 34,157 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 14,830 | 7,806 | 526 | 132 / 118 |  |
| 17 | PNG: 1.4 million empty chunks | 34,183 | SUSPICIOUS, `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | 8,381 | 1,194 | 81 | 132 / 118 | c2pa.thumbnail.claim: PNG with more than 100000 markers and chunks in the pictures of this |
| 18 | PNG: one 16 MiB IDAT | 17,906 | SAFE, `ENGINE_PDF_ATTACHMENTS_VERIFIED` | 10,451 | 4,203 | 309 | 148 / 130 |  |

- **The old resource-exhaustion case (06)** completed on staging in 7,155 ms (pdf-chains 806 ms),
  not verified ("more than 100000 CBOR or JSON items"), with every scanner completed. At `c873706` it
  took 5,080 ms and 1,996 MiB locally, far over the staging worker's 256 MB.
- **Memory.** The scan response carries no memory figure, and the instance memory graph needs a
  dashboard sign-in, which was not done. What staging shows: every case completed with the same
  scanner statuses as locally, inside the worker's `RLIMIT_DATA` of 256 MB (an allocation beyond it
  fails, and the scanner would have reported `failed`); the service logs from 19:42 to 21:10 have no
  memory error, kill, restart or traceback, and the only scanner failures are the two scans of the
  truncated PDF (by design). Measured peak (local, Windows): 150 MiB working set / 133 MiB private
  at most, of which about 68 MiB is the warmed-up process.
- **Time.** On the cases that take over 300 ms locally, pdf-chains on staging takes 13-16x the whole
  local scan (the free instance's CPU share, as in the `9882cbf` report). The slowest case is the
  combined one (19): 15.5 s whole scan, 9.1 s in pdf-chains, against 574 ms locally. The worker's
  timeout is 30 s and its CPU limit 20 s, so the margin on staging is about 2x. A PDF that exceeded
  it would end the worker and produce UNABLE_TO_SCAN (fail safe), not SAFE; with one concurrent
  scan on staging it would hold the service for up to 30 s. Before this change the same PDFs were
  reported unverified without their C2PA content being read.

### Risky C2PA cases (test 4)

Unified engine (the original engine's code is unchanged and was not re-run on these; locally it
gives SUSPICIOUS or, for C70 and C71, MALICIOUS on every one).

| case | verdict | non-INFO rules | attachment rule | whole scan (ms) |
|---|---|---|---|---|
| `C01-cbor-only` | SAFE | - | ENGINE_PDF_ATTACHMENTS_VERIFIED | 6,042 |
| `C04-static-svg-icon` | SAFE | - | ENGINE_PDF_ATTACHMENTS_VERIFIED | 6,350 |
| `C09-with-verified-odt` | SAFE | - | ENGINE_PDF_ATTACHMENTS_VERIFIED | 6,572 |
| `C10-svg-script` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW`, `yara-x:SVG_Script_Content:MEDIUM` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,395 |
| `C11-svg-onload` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW`, `yara-x:SVG_Script_Content:MEDIUM` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,504 |
| `C19-svg-set-href` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW`, `yara-x:SVG_Script_Content:MEDIUM` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,591 |
| `C21-html-in-data-box` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,986 |
| `C14-svg-external-image` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,706 |
| `C35-external-reference` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,271 |
| `C50-truncated` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,258 |
| `C53-nesting-too-deep` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,252 |
| `C54-too-many-boxes` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,281 |
| `C30-mz-declared-jpeg` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,392 |
| `C36-mz-as-c2pa-manifest` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,278 |
| `C37-store-named-html` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,138 |
| `C70-auto-js-exports-manifest` | MALICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW`, `pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT:HIGH`, `pdf:PDF_JAVASCRIPT:MEDIUM`, `pdf:PDF_JAVASCRIPT_EXPLOIT_API:HIGH`, `yara-x-engine:ENGINE_PDF_JavaScript_With_Automatic_Trigger:MEDIUM` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,351 |
| `C71-auto-launch-manifest` | MALICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW`, `pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT:HIGH`, `pdf:PDF_LAUNCH_ACTION:HIGH`, `yara-x:PDF_Launch_Action:HIGH` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,365 |
| `C24-user-link-javascript` | SUSPICIOUS | `pdf-chains:ENGINE_PDF_ATTACHMENTS_UNVERIFIED:LOW`, `pdf:PDF_JAVASCRIPT:MEDIUM` | ENGINE_PDF_ATTACHMENTS_UNVERIFIED | 6,269 |

Each risky case kept its warning and named the first item that failed. C10, C11, C19 (scripted SVG)
also keep YARA-X `SVG_Script_Content` MEDIUM; C70 and C71 stay MALICIOUS with the chain rule's
`ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT` HIGH and the reference HIGHs listed, identical to the
local result and to `9882cbf` (no HIGH lost, prediction P9). The three benign cases are the only
SAFE ones, as locally.

### Regression cases (test 5)

The 12 cases of the `9882cbf` staging regression, both engines:

| case | original | unified | ms (original / unified) |
|---|---|---|---|
| `files/pdf-07-libreoffice-hybrid.pdf` | SUSPICIOUS | SAFE | 5,810 / 6,376 |
| `1-pdf-clean` | SAFE | SAFE | 5,956 / 6,273 |
| `S01-empty-tree` | SUSPICIOUS | SAFE | 5,985 / 6,424 |
| `S06-mz-bytes-text-name` | SUSPICIOUS | SUSPICIOUS | 6,538 / 6,519 |
| `S11-incremental-update-removes-attachment` | SUSPICIOUS | SUSPICIOUS | 6,140 / 6,188 |
| `S12-broken-xref` | SUSPICIOUS | SUSPICIOUS | 5,987 / 6,434 |
| `S13-marker-in-page-text` | SUSPICIOUS | SUSPICIOUS | 6,398 / 6,366 |
| `corrupt-truncated-pdf` | UNABLE_TO_SCAN | UNABLE_TO_SCAN | 5,995 / 6,474 |
| `S15-auto-js-exports-attachment` | MALICIOUS | MALICIOUS | 6,221 / 5,999 |
| `S16-auto-launch-embedded-exe` | MALICIOUS | MALICIOUS | 5,829 / 6,030 |
| `S17-empty-tree-auto-launch` | MALICIOUS | MALICIOUS | 5,736 / 6,159 |
| `c7b-docx-ddeauto-cmd` | MALICIOUS | MALICIOUS | 5,984 / 6,128 |

All 24 matched the local `e2eb2c7` results, which equal the `9882cbf` results for every one of
these cases (none carries a C2PA manifest). HIGH findings on S15, S16, S17 and c7b are unchanged
in both engines.

### Scanner execution and isolation (test 6)

All 67 scans (61 over HTTP, 6 in the Lab): strict isolation required and `isolation_missing []`;
the original engine listed its 4 scanners and the unified engine its 9; every applicable scanner
completed, except on `corrupt-truncated-pdf`, where pdf and custom (and pdf-chains in the unified
engine) failed on the malformed input and the verdict is UNABLE_TO_SCAN, as designed. Network
checks as before: loopback only false because of the inert, down `tunl0`; no usable route.

### HTTP failure checks (test 8)

| Check | Expected | Result |
|---|---|---|
| Token request for an oversized file (10 MiB + 1) | 413 | 413 |
| Upload over 10 MiB to `/scan` | 413 | 413 |
| Unknown engine (`?engine=fastest`) | 400 | 400 |
| Invalid token (`?engine=unified`) | 401 | 401 ("Invalid scan token" in the service log) |

## Latency

| Group | Scans | Whole scan, median (range) | pdf-chains, median (max) |
|---|---|---|---|
| Resource cases, unified | 19 | 7,370 ms (6,425-15,480) | 899 ms (9,097) |
| Risky and benign C2PA cases, unified | 18 | 6,350 ms (6,042-6,986) | 2 ms (91) |
| Regression, original | 12 | 5,986 ms (5,736-6,538) | - |
| Regression, unified | 12 | 6,320 ms (5,999-6,519) | 1 ms (97) |
| APA D1-D3, original -> unified (Lab) | 6 | 6,043-6,649 -> 6,791-6,867 ms | D1 210 ms, D2 207 ms |

Whole-scan time is mostly the worker's start-up, as on `9882cbf` (5.9-7.4 s there). The change
adds time only where a PDF carries a C2PA store; on an ordinary-sized store (D1, 24 KB; C01-C70,
about 2 KB) it is within the run-to-run variation.

## Verdict changes

On staging, exactly as locally:

- **D1 (original APA report), unified: SUSPICIOUS -> SAFE.** The only verdict change among the
  real documents tested here. Original engine unchanged (SUSPICIOUS).
- Synthetic benign C2PA stores C01, C04, C09 and the 10 limit cases that verify (01, 04, 07, 09, 11,
  13, 14, 16, 18, 19): SAFE in the unified engine (SUSPICIOUS at `9882cbf`, which verified no C2PA
  store), as in the local evaluation, where the full set of 57 unified SUSPICIOUS -> SAFE changes
  is listed (README, "Which documents changed verdict").
- Nothing else changed: D2 and D3, every risky case, every regression case and every original-engine
  verdict are as before.

## Differences from local testing

- Verdicts, rules and scanner statuses: none (65 of 65, and the 6 Lab scans).
- Time: 6-15 s per scan on staging, mostly worker start-up; the C2PA work 13-16x the local time
  on the long cases (above).
- Memory: not measured on the host (above).

## Rollback

Not needed: no security regression, no resource-limit failure. Target, if needed later:
`dep-dbps71gn74is738thlo0`, commit `9882cbf15e4681d16dc9d39ac1701f109db00b0e` (deactivated, not
deleted):

    render deploys create srv-dbelc2jrjlhs7382nv5g --commit 9882cbf15e4681d16dc9d39ac1701f109db00b0e --wait

That restores the `9882cbf` behaviour: every unified SUSPICIOUS -> SAFE change above is undone (D1
SUSPICIOUS again); the original engine is the same in both. Production is not involved and needs
separate approval.
