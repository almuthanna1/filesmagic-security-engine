# Staging deployment of the PDF accuracy change (`9882cbf`)

Approved by the user for the Render staging service `srv-dbelc2jrjlhs7382nv5g` only. Production
FilesMagic, the frozen release (`2d586f6`, tag `custom-engine-freeze-2026-11-09`) and the Vercel Lab
were not changed. No malware was uploaded: only the three APA report variants (private; hashes
below) and inert synthetic or authored benign fixtures.

## Before deploying

| Check | Result |
|---|---|
| Commit | `9882cbf15e46...` = head of `origin/feature/unified-pdf-accuracy` |
| CI | run 42936324849 success: backend (Linux, non-root) 1032 passed, tunl0 isolation rerun 31 passed, Docker image, Lab build |
| Original engine unchanged | `git diff 2d586f6 9882cbf -- app` touches only `app/engine/{correlate,pdf_attachments,pdf_chains}.py`; `app/scanners`, `app/rules`, `app/decision`, `app/worker.py`, `app/main.py` unchanged; the worker runs `correlate()` only with `--engine=unified` |
| Live deploy and rollback target | `dep-dbpll8rl550s73dnav5g`, commit `2d586f6` (live since 2026-11-10T17:56Z); auto-deploy off; service branch `feature/custom-unified-engine-nov18` (unchanged) |
| Guards | the new rule removed a LOW `PDF_Embedded_File` with complete evidence; it kept it when MEDIUM, HIGH or CRITICAL; a forged "accounts for" line on `PDF_LAUNCH_ACTION`, `PDF_EMBEDDED_EXECUTABLE` or `ENGINE_PDF_AUTO_CHAIN_LAUNCH` (HIGH, CRITICAL) removed nothing; a failed chain or PDF scanner, or a repaired structure, kept the finding; 92 related tests passed |

## Deployment

`render deploys create srv-dbelc2jrjlhs7382nv5g --commit 9882cbf15e4681d16dc9d39ac1701f109db00b0e --wait`:
`dep-dbps71gn74is738thlo0`, created 2026-11-11T01:23:18Z, live 01:23:49Z. `/health` afterwards (and
again at 03:56Z): `commit 9882cbf15e4681d16dc9d39ac1701f109db00b0e`, `engines [reference, unified]`,
`scanners_registered 4`, `scanners_ready 4`, `auth_configured true`. The previous deploy is
deactivated, not deleted.

## The three APA variants (Lab, Compare Both)

| | SHA-256 (prefix) | Original engine | Unified engine | Same as local `9882cbf`? |
|---|---|---|---|---|
| D1 original | `a851ee59` | SUSPICIOUS: `PDF_Embedded_File` LOW, `PDF_EMBEDDED_FILE` LOW | SUSPICIOUS: `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` LOW (Content Credentials not verified) | yes |
| D2 metadata removed | `36cba588` | SUSPICIOUS: `PDF_Embedded_File` LOW | **SAFE**: `ENGINE_PDF_NO_ATTACHMENTS` INFO, "byte 74130: the key /EmbeddedFiles of object 172 0, an empty name tree" | yes |
| D3 corrected | `1f35e349` | SAFE, no findings | SAFE, no findings | yes |

The original engine's verdicts are the ones it gave before this change (frozen code, same bytes).
All six scans: strict isolation required, `isolation_missing []`, every applicable scanner completed.
The correlation evidence shows the removed findings verbatim ("raw yara-x:PDF_Embedded_File LOW: ...").
Whole scan (worker start-up included), original -> unified: D1 7201 -> 6627 ms, D2 6370 -> 7420 ms,
D3 6220 -> 6821 ms; scanner work 100-107 -> 392-403 ms.

## Regression cases (HTTP: Lab token -> engine `/scan`, as the browser does)

Each scan was compared with the local run of the same commit on the same bytes: verdict, non-INFO
rules and scanner statuses identical; plus engine identity, commit, uploaded hash, CORS, complete
analysis and `isolation_missing []` (the truncated PDF is UNABLE_TO_SCAN by design).

| Case | Kind | Original | Unified | ms (original / unified) |
|---|---|---|---|---|
| `files/pdf-07-libreoffice-hybrid.pdf` | benign, verified ODF attachment | SUSPICIOUS | SAFE | 6327 / 6543 |
| `1-pdf-clean` | benign | SAFE | SAFE | 5857 / 6476 |
| `S01-empty-tree` | no attachment | SUSPICIOUS | SAFE | 6471 / 6533 |
| `S06-mz-bytes-text-name` | attachment, harmless name and MIME | SUSPICIOUS | SUSPICIOUS | 5916 / 6495 |
| `S11-incremental-update-removes-attachment` | ambiguous | SUSPICIOUS | SUSPICIOUS | 6032 / 6698 |
| `S12-broken-xref` | malformed | SUSPICIOUS | SUSPICIOUS | 6193 / 6184 |
| `S13-marker-in-page-text` | ambiguous | SUSPICIOUS | SUSPICIOUS | 6062 / 6567 |
| `corrupt-truncated-pdf` | malformed | UNABLE_TO_SCAN | UNABLE_TO_SCAN | 5861 / 6480 |
| `S15-auto-js-exports-attachment` | dangerous | MALICIOUS | MALICIOUS | 6063 / 6251 |
| `S16-auto-launch-embedded-exe` | dangerous | MALICIOUS | MALICIOUS (the 3 reference HIGH kept, plus the chain rule's HIGH) | 6789 / 6780 |
| `S17-empty-tree-auto-launch` | dangerous | MALICIOUS | MALICIOUS (both reference HIGH kept, plus the chain rule's; only the YARA-X LOW removed) | 6891 / 6835 |
| `c7b-docx-ddeauto-cmd` | dangerous (Office) | MALICIOUS | MALICIOUS | 6708 / 6453 |

24 of 24 scans matched; HTTP failure checks 4 of 4 (oversized token request 413, oversized upload
413, unknown engine 400, invalid token 401). The first run (2026-11-11, 18 scans, all matched)
stopped before S16 when this machine aborted a connection to the Lab's token route while waiting
out its 12-tokens-per-15-minutes limit (WinError 10053; no response from staging was involved). It
was resumed from S16 into new files: `staging-9882cbf-regression-resume.json`, 0 client errors.

## Differences from local testing

- Verdicts, rules and scanner statuses: none.
- Time: about 10x slower in all. A scan takes 5.9-7.4 s on staging against about 0.6 s locally,
  almost all of it worker start-up; on 2026-11-07 (`7b4f838`) staging took 6335 / 6513 ms for the
  same `1-pdf-clean` (5857 / 6476 ms now), so this is the instance's baseline, not this change. Scanner times are 20-30x the
  local ones and fall near steps of about 90-100 ms (pdf 82-93 ms against about 3 ms locally;
  pdf-chains 289-301 ms against 12-15 ms), which fits a CPU quota of the free instance; the 86 ms
  "not applicable" reading of 2026-11-10 fits the same pattern. Not measured on the host itself.

Rollback, not needed: `render deploys create srv-dbelc2jrjlhs7382nv5g --commit
2d586f651a68a9f45b061c2e8cbb8dd136be645a --wait`.
