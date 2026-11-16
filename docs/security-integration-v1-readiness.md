# Security integration v1: validation and readiness, November 15–16, 2026

**Build:** branch `feature/production-scan-integration-v1` (PR #23). **Contract:** [security-integration-v1.md](security-integration-v1.md).
**Handoff:** [security-integration-v1-handoff.md](security-integration-v1-handoff.md). Nothing has been deployed;
production (`srv-db3r5cc9v7es73e57frg`, live `e6fdbd4`, deploy `dep-db5b3k2d0e5s73er59bg`) and staging
(`srv-dbelc2jrjlhs7382nv5g`, live `840a300`, deploy `dep-dbrsv0ei0phs73benb70`) are unchanged.

## 1. Combined accuracy regression (252 samples)

**Status: completed and verified.** Evidence: [`docs/evidence/combined-regression-1e86627/`](evidence/combined-regression-1e86627/)
(`summary.md` / `summary.json` per run. Per-sample findings stay local, because they quote private documents).

Corpus:
- 252 samples: the 12 frozen cases, the in-repo benign corpus, the C2PA public set and the local dev and
  held-out sets;
- every sample is benign or an inert synthetic construction;
- no malware or EICAR.

Each sample was scanned by `worker.run` (a fresh isolated worker per scan). The verdict is computed exactly as
`/scan` computes it, **including the coverage gate**. The older `evaluation.cases.verdicts` ignores that gate,
so it understates UNABLE_TO_SCAN on every build since PR #21.

Platform: Windows 11, Python 3.12, so local latency is not hosted latency (§5).

**Runs:**
1. Three builds × 3 trials, 2026-11-15 20:07–20:52:
   - the candidate tree at `ca8ca9a` with the Phase 3 edits in progress;
   - `90718ff` (pypdf 7.0.1 evidence);
   - `840a300` (the Nov 14 PDF coverage regression build, live on staging).
2. Candidate re-run at the committed `1e86627`, clean tree, 1 trial, plus a memory pass with one fresh process
   per sample. It is **identical to run 1**: 0 differences in verdict, reasons or authorization over all
   504 sample×engine results.

| Measure (unified engine) | candidate `1e86627` | `90718ff` | `840a300` (staging) |
|---|---|---|---|
| SAFE / UNABLE / SUSPICIOUS / MALICIOUS | 153 / 5 / 85 / 9 | 158 / 0 / 85 / 9 | 153 / 5 / 85 / 9 |
| Detection TP / FP / TN / FN | 55 / 9 / 134 / 0 | 55 / 9 / 134 / 0 | 55 / 9 / 134 / 0 |
| Detection precision / recall / F1 | 0.859 / **1.000** / 0.924 | same | same |
| Detection false-positive rate | 0.063 | 0.063 | 0.063 |
| Gate (anything but SAFE blocks) FP / FPR | 14 / 0.098 | 9 / 0.063 | 14 / 0.098 |
| Scanner failures | 1 (`CH07` `pdf-chains` invalid structure: encrypted, fail-closed) | 1 | 1 |
| Worker errors / non-deterministic results | 0 / 0 | 0 / 0 | 0 / 0 |
| Samples with incomplete coverage | 14 | 0 (no coverage gate) | 14 |
| Frozen-case mismatches | 0 | 0 | 0 |
| Latency median / P95 / max, ms (3 trials) | 547 / 820 / 1,120 | 561 / 800 / 1,241 | 545 / 724 / 925 |
| Re-run latency median / P95 / max, ms | 529 / 713 / 983 | — | — |
| Peak memory, one scan, fresh process | **98.6 MiB** working set (`L41`); median 60.7; after loading 61.0; peak private 81.0 | — | — |

The reference engine is unchanged in every build: 97 SAFE / 143 SUSPICIOUS / 12 MALICIOUS. The memory figure is
the in-process scan peak, measured on Windows. The isolated worker's Linux `RLIMIT_DATA` cap is 320 MB.

**Comparison with the baselines:**
- **`840a300` → candidate:** 0 changed results. The receipt work changed no verdict.
- **`90718ff` → candidate:**
  - 5 changes, all benign `SAFE → UNABLE_TO_SCAN`: `L40`, `L46`, `L47`, `CH05` (`PDF_ATTACHMENT_COVERAGE_INCOMPLETE`),
    and `CD01` (parser repairs + attachment coverage).
  - These are PR #21's coverage fail-closed, which `90718ff` predates; all 5 are `consent_required`, not deny.
- **Regressions:**
  - **No sample flagged by any baseline is SAFE now.**
  - No unified verdict is weaker than either baseline.
  - Recall stays 1.0 on every positive class (`attachment`, `ambiguous`, `dangerous`, `c2pa-*`).
- **pypdf 7.0.1 evidence:** the LZW-damaged page (`bad-data.pdf`), which `90718ff` called SAFE, is UNABLE_TO_SCAN
  with `PDF_CONTENT_LZW_DECODE_FAILED` on the candidate. Covered by `tests/test_pdf_integrity.py` and the
  hosted acceptance (`evaluation/conversion_acceptance.py`, `unable-damaged-page-content`).

**Authorization outcomes (candidate):**

| Class | allow | consent_required | deny |
|---|---|---|---|
| benign (101) | 90 | 10 | 1 |
| c2pa-benign (38) / no-attachment (4) | 35 / 4 | 3 / 0 | 0 |
| dangerous (5) | 0 | 0 | **5** |
| attachment, ambiguous, c2pa-active/deceptive/malformed (50) | 0 | 50 | 0 |
| frozen cases (22) | 5 | 14 | 3 |

Every MALICIOUS sample is denied (`malicious_not_denied: []`).

**Benign samples that do not convert directly (11 of 101):**
- 3 IRS forms (`f1040`, `fw4`, `fw9`): XFA + auto-run JavaScript + embedded file → SUSPICIOUS, consent.
- `docx-05` local template → SUSPICIOUS, consent.
- `CH07` encrypted → consent.
- 5 coverage-incomplete → UNABLE, consent.
- **`CD03` → MALICIOUS → deny.** c2pa-rs `basic-attachments.pdf`, a C2PA-study dev control. Its automatic
  document script (`ADBE::FileAttachmentsCompatibility`) triggers `PDF_JAVASCRIPT_EXPLOIT_API` (HIGH).
  - It is the known false positive recorded in the C2PA study (`docs/evidence/c2pa-accuracy-e2eb2c7/README.md`
    on `feature/unified-c2pa-accuracy`).
  - It is unchanged across all three builds.
  - Fixing it means changing the frozen engine, a separate validated release.

Of 101 benign documents, 89.1% are converted directly and 1% are blocked outright.

**Not measured here:**
- **Genuine malware.** That needs the isolated VM study; see `docs/genuine-malware-evaluation-plan.md`, which is
  not run.
- **Hosted latency.** See §5.

Detection recall is measured on synthetic dangerous constructions and is not evidence of real-world malware
detection rates.

## 2. Scanner readiness criteria

A deployment may authorize conversions only when **all** hold (`/health` `ready_for_conversion`):

1. The unified engine is enabled (`SECURITY_ENGINE_RESEARCH_ENGINES=1`), and all 10 unified scanners loaded in
   the API process. YARA-X rules compiled; a scanner that failed to load makes every scan `SCANNER_NOT_READY`.
2. `SECURITY_ENGINE_REQUIRE_ISOLATION=1`.
3. A conversion token key, set and different from the Lab key.
4. A receipt key set (`receipt_key_id` reported).

Per scan, a receipt is issued only for a valid worker report with the exact roster and every required
isolation control true (contract §5). `/health` cannot prove isolation works on the host: only a real scan's
`isolation_verified: true` does, so every deployment is followed by a probe scan (§4).

## 3. Security review (hostile client)

Each item was checked against the code and has an automated test in `tests/test_integration_v1.py`
(62 tests).

| # | Requirement | Result | Test(s) |
|---|---|---|---|
| 1 | MALICIOUS never authorizes | Policy step 1 denies; receipt says `deny`; the verifier rejects MALICIOUS-not-deny | `test_malicious_is_receipted_but_never_authorizing`, `test_a_malicious_answer_stays_denied_whatever_the_body_says`, `test_receipt_with_unverified_isolation_or_authorizing_malicious_is_rejected` |
| 2 | Editing response JSON cannot forge SAFE | Only signed claims count; any claim change breaks the signature | `test_tampered_receipts_are_rejected`, `test_a_malicious_answer_stays_denied_whatever_the_body_says` |
| 3 | No reuse for another document | `sha256` + `size` bound and checked | `test_receipt_verifies_and_binds_the_bytes` |
| 4 | No modification without invalid signature | Ed25519 over the exact payload bytes | `test_tampered_receipts_are_rejected`, `test_malformed_receipts_only_ever_raise_receipt_errors` |
| 5 | Expired receipts rejected | 300 s lifetime, 30 s skew | `test_receipt_expires_after_five_minutes` |
| 6 | Key ID cannot be overwritten by scanner output | Found and **fixed** in the first session (reserved claims set last); now tested for every reserved claim | `test_outcome_data_cannot_override_reserved_receipt_claims`, `test_key_rotation` |
| 7 | Missing/incorrect scanner versions fail verification | **Gap fixed:** the reference verifier did not check engine or build. Now always requires `engine == "unified"`, and `pins=` makes a missing claim `RECEIPT_WRONG_TYPE` and a different value `RECEIPT_BUILD_MISMATCH` | `test_a_real_receipt_verifies_against_the_pinned_build`, `test_a_different_build_fails_verification` (commit, roster, versions, ruleset), `test_missing_version_claims_or_another_engine_fail_verification` |
| 8 | Crashes/infrastructure failures never override-eligible | Operational reasons deny, no receipt | `test_worker_failures_deny_without_receipt` (real crash, garbage, timeout), `test_wrong_scanner_roster_denies`, `test_scanner_not_ready_denies`, `test_scanner_programming_error_denies` |
| 9 | Failed/unverified isolation cannot authorize | `ISOLATION_UNVERIFIED` / `ISOLATION_NOT_ENFORCED`, no receipt | `test_unverified_isolation_denies_even_a_clean_file`, `test_isolation_not_enforced_denies`, `test_strict_worker_refusal_is_operational` |
| 10 | Missing signing keys fail closed | No receipt key → no receipt, not ready; no token key → `AUTH_NOT_CONFIGURED` | `test_no_receipt_without_a_receipt_key`, `test_no_scan_key_configured_refuses_everything` |
| 11 | Lab tokens cannot mint receipts | Issuer = verifying key, set after the claims, so a Lab token claiming `"issuer": "conversion"` still gets none. **Gap fixed:** a shared Lab/conversion key now makes `/health` not ready | `test_security_lab_tokens_keep_working_and_never_get_receipts`, `test_a_lab_token_claiming_the_conversion_issuer_gets_no_receipt`, `test_shared_lab_and_conversion_key_is_not_ready_and_issues_no_receipt` |
| 12 | A conversion token buys one scan | `jti` consumed on first use, even for other bytes | `test_expired_and_replayed_tokens_are_refused`, `test_one_token_buys_one_scan_even_for_other_bytes` |
| 13 | Replay protection and limits documented | Contract §5 step 9 (one receipt per token, `rid` single use) and §12 (restart window, single instance) | — |
| 14 | No secrets or document content in logs | Logs carry request ID, codes, a 16-hex hash prefix, size and verdict; never content, filename, token, receipt or full hash | `test_logs_carry_no_document_content_filename_token_or_receipt`, `test_receipt_private_key_never_stays_in_the_environment`, `test_health_reports_conversion_readiness` |

**Also found and fixed:** a PDF that pypdf cannot open makes `pdf-integrity` fail as "unexpected" (its error
class declares no malformed causes), so the outcome is `SCANNER_INTERNAL_ERROR` → deny. That is fail-closed, but
the user was told "a problem on our side". The explanation for a scanner error alone is now neutral
(`test_scanner_error_alone_is_explained_without_blaming_either_side`). Reclassifying it as `DOCUMENT_MALFORMED`
would change engine code (`app/engine`, frozen) and needs its own validated release.

**Accepted limitations** (contract §12): in-memory replay store (one instance; restart window); the worker's
report is trusted, so a parser exploit that takes over the worker could forge it; failed-auth throttling is
per address.

## 4. Staging deployment plan (proposed, **not executed**)

Target: `filesmagic-security-engine-staging` (`srv-dbelc2jrjlhs7382nv5g`, workspace `tea-dbel9v3ncjis73ek9cog`,
Free, Virginia, auto-deploy off, branch setting `feature/custom-unified-engine-nov18`). Production is not touched.

**Current state (2026-11-16).** The live deploy is `dep-dbrsv0ei0phs73benb70` = `840a300`. `/health` reports:
- unified-only, so `SECURITY_ENGINE_RESEARCH_ENGINES=1` and `SECURITY_ENGINE_PUBLIC_UNIFIED_ONLY=1`;
- `auth_configured: true`, i.e. the Lab key is set.

The Nov 14 evidence shows strict isolation verified on this host (`net_fallback_tunnel_inert`, all route checks
true). The staging Lab (`filesmagic-security-lab-staging`) points to this service.

**Proposed changes, each needing approval:**

| # | Change | Value | Effect |
|---|---|---|---|
| 1 | Add env `SECURITY_ENGINE_CONVERSION_TOKEN_PUBLIC_KEY` | `conversion-token/public.txt`, key ID `d14ec237c6298c95` | Render restarts the current build; `840a300` ignores the variable |
| 2 | Add env `SECURITY_ENGINE_RECEIPT_PRIVATE_KEY` (secret) | `receipt/private.txt`, key ID `05a8f2c2fb2eb9e7` | Same |
| 3 | Deploy `render deploys create srv-dbelc2jrjlhs7382nv5g --commit <final PR #23 SHA>` | — | Staging Lab keeps working (additive fields; Lab tests pass) |

**Not changed:**
- the Lab key, `SECURITY_ENGINE_REQUIRE_ISOLATION=1`, the research/unified-only flags, CORS;
- the branch setting and auto-deploy;
- the plan (Free).

There is no persistent disk; no evaluation data lives on the service. Both key pairs were generated on
2026-11-16 with `filesmagic-engine/scripts/scan_keys.py new` into
`C:\Users\almut\fm-staging-keys-20261116\{conversion-token,receipt}`. That folder is outside every repository;
the keys have not been shown or uploaded. Values are pasted only in the Render dashboard as secrets.

**After deploy:**
1. `GET /health` shows `commit` = the SHA, `ready_for_conversion: true` and `receipt_key_id: 05a8f2c2fb2eb9e7`.
2. Run the conversion acceptance:
   ```
   python -m evaluation.conversion_acceptance --api https://filesmagic-security-engine-staging.onrender.com \
     --commit <sha> --token-key <keys>/conversion-token/private.txt --receipt-public-key <keys>/receipt/public.txt \
     --lab https://filesmagic-security-lab-staging.vercel.app --out docs/evidence/integration-v1-staging/<sha>.json
   ```
   This checks:
   - health;
   - SAFE (PDF, DOCX, XLSX), SUSPICIOUS, eligible UNABLE_TO_SCAN, encrypted and MALICIOUS, each receipt verified
     and pinned;
   - missing, invalid, wrong-key, expired and replayed tokens, a wrong hash, and over 10 MiB;
   - a tampered receipt and a receipt for another document;
   - that a Lab token gets no receipt.

   Trusted benign and inert synthetic files only.
3. Run the Lab acceptance in token-limit batches:
   `python -m evaluation.lab_acceptance --lab <lab> --api <api> --require-isolation --batch N --out ...`.
   Then `--failure-checks-only`.
4. Operational failures (worker crash, timeout, isolation loss) cannot be induced on a hosted service without
   changing it. They are covered by `tests/test_integration_v1.py` and the CI Linux isolation suite.

**Rollback:** `render deploys create srv-dbelc2jrjlhs7382nv5g --commit 840a300c1edf4682cbd4ba7ecc7f183ba281983e`
(or roll back to `dep-dbrsv0ei0phs73benb70`). The two new variables can stay (ignored by `840a300`) or be deleted.

## 5. Render resources

| Measurement | Value | Source |
|---|---|---|
| Free cold start (sleeping instance → first `/health`) | **22.3 s**, then 0.18 s warm | `curl` against staging, 2026-11-16 |
| Free hosted scan, small PDFs | **6.0–7.3 s**, of which the scanners spent **≤ 0.4 s** | Nov 14 hosted evidence (`staging-840a300c-2026-11-14.json`) |
| Free, heavy C2PA limit case | 15.5 s of the 30 s worker limit (13–16× local) | `docs/evidence/c2pa-accuracy-e2eb2c7/staging-e2eb2c7.md` on branch `feature/unified-c2pa-accuracy` (`d456d99`): 15.5 s whole scan vs 574 ms locally |
| Local (Windows) unified scan, per sample incl. worker start | see §1 | combined regression |
| Peak memory of one unified scan | see §1 | combined regression, memory pass |
| Worker memory limit | `RLIMIT_DATA` 320 MB; API process ~70 MiB | `app/worker.py` |
| Production rehearsal at 0.5 CPU / 512 MB | 137/137 checks passed (90718ff build) | filesmagic-engine run 43251216160 |

**Assessment of Free (0.1 CPU, 512 MB, sleeps after idle):**
- **Not suitable** for a mandatory scanning service.
- **Every scan pays a ~6 s worker start-up at 0.1 CPU.** Each scan starts a fresh isolated worker: Python
  imports, YARA-X compilation, namespaces.
- **Sleep adds 22 s to the first request.** The Conversion Engine's 60 s timeout leaves little room for a cold
  start plus a heavy document, and a merge of several files runs its scans serially.
- **One scan at a time.** Simultaneous users queue behind the Conversion Engine's lock; at 6–7 s a scan, ten
  waiting users exceed the 60 s timeout.
- **Free instance hours are shared.** The FilesMagic workspace already runs several Free services, which share
  the workspace's monthly Free instance hours.

**Recommendation: Starter (0.5 CPU / 512 MB), $7/month** for the Security Engine:
- no sleep;
- 5× the CPU, so an estimated ~1.2–1.5 s per small document; this is an estimate to measure on the first
  Starter deploy;
- the same memory, which fits:
  - concurrency 1;
  - the measured peak (§1) under the 320 MB worker cap.

Keep `SECURITY_ENGINE_MAX_CONCURRENT_SCANS=1`. Standard (1 CPU / 2 GB, $25/month) is only needed for 25 MB or
concurrency > 1, neither of which is validated. **No plan change has been made; it needs approval.** The
Conversion Engine also runs on Free; its plan is a separate decision.

## 6. Production release checklist

- [ ] PR #23 reviewed; CI green on its final SHA.
- [ ] Combined regression on the final SHA: no flagged sample becomes SAFE, and no new false positive (§1).
- [ ] Staging deployed (approved), §4 steps 1–3 all pass; evidence committed.
- [ ] Production plan → Starter (approved, $7/month).
- [ ] Production keys generated (separate from staging); conversion token public key + receipt private key set
      on the production Security Engine; private token key + receipt public key on the Conversion Engine.
- [ ] Production Security Engine env:
  - `REQUIRE_ISOLATION=1`;
  - `RESEARCH_ENGINES=1`;
  - `PUBLIC_UNIFIED_ONLY=1`;
  - no Lab key;
  - CORS unset.
- [ ] Deploy the SHA to production (approved); `/health` `ready_for_conversion: true`; one probe scan shows
      `isolation_verified: true` **on the production host** (Oregon, a different region from staging).
- [ ] Conversion Engine PR #2 and website PR #7 reviewed against the final Security Engine SHA,
      deployed to staging, and tested end to end with verified host isolation; copy approved.
      Local integration was rehearsed against `ca8ca9a`, not the final `1451af8` build.
- [ ] Enable the gate.

## 7. Production rollback

1. Disable the gate in the Conversion Engine first (or roll it back), so no conversion depends on the scanner.
2. `render deploys create srv-db3r5cc9v7es73e57frg --commit e6fdbd421058996415fccb8808cdc5376c36f5f5`
   (deploy `dep-db5b3k2d0e5s73er59bg`, the reference engine).
3. The new variables can stay; `e6fdbd4` ignores them.
4. Plan downgrade only after the rollback is confirmed.

## 8. Remaining blockers before production

1. **Staging deployment and hosted acceptance not done.** They need approval (§4). Until then:
   - receipts and `isolation_verified: true` have not been shown on a Render host with this build;
   - the local Windows dry run correctly refused every receipt (`ISOLATION_NOT_ENFORCED`), and passed every
     authentication, integrity and size check.
2. **Conversion Engine and website are implemented but not deployed to staging.** The current
   Conversion Engine PR #2 (`feature/security-gate`) and website PR #7
   (`feature/security-scan-ui`) now use signed receipt verification, the 10-scanner
   unified roster, server-side consent storage, and the `scan_consent` flow. They
   were rehearsed locally against the earlier Security Engine PR #23 commit
   `ca8ca9a` with in-process isolation simulation. **This does not establish
   hosted isolation or integrated staging acceptance against the final `1451af8`
   build.** Both PRs remain unmerged. See the [handoff](security-integration-v1-handoff.md).
3. **Render plan.** Free is not suitable for a mandatory gate (§5); Starter ($7/month) needs approval.
4. **Production keys** are not generated, and must be separate from staging's.
5. **Genuine-malware detection not evaluated.** The accuracy evidence is synthetic and benign. The VM study is
   still blocked on approvals.
6. **Copy and consent UX approval.** Public wording for SAFE and for the consent dialog.
7. **Known accepted limitations** (§3): single-instance replay store, trusted worker report, `CD03` false
   positive, unopenable PDFs reported as a scanner error (deny).
