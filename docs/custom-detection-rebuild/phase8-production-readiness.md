# Phase 8: integration and production readiness

Date: 2026-11-21. Production is unchanged. Nothing here has been deployed to production, merged into
`main`, or changed on a production Render or Vercel service.

## 1. Release candidates

| | Repository | Branch | Commit | Production now |
|---|---|---|---|---|
| Security Engine | `almuthanna1/filesmagic-security-engine` | `feature/custom-malware-detection-rebuild` | `26ac5da1bc5e782ff4e934cdc2fdf6f5bfa95038` | `b6774bea199f13170a4dfb144048f7d63f59b859` |
| Conversion Engine | `almuthanna1/filesmagic-engine` | `feature/custom-security-engine-integration` | `9ee7e5d87a6b8de0404032adeecce6bfc1904de4` | `482e72459367196ac1a808846d630fb5f24c8300` |
| Frontend | `FilesMagic-frontend` | `main` (no change needed) | `ffd8fa0` | same |

The Security Engine release is tag `release/unified-engine-rc1` (= `26ac5da`). Later commits on the
branch change only `docs/`. Deploy the tag, not the branch head: the pin must equal the deployed commit.

Both branches are fast-forwards of their production `main` (Security Engine: 13 commits; Conversion
Engine: 1 commit). This matters: the Conversion Engine trusts receipts from one exact commit, so the
Security Engine must be deployed at `26ac5da` itself. A merge commit or a squash would produce a
different SHA, and every conversion would be refused.

Security Engine commits after the seven rebuild phases:

| Commit | Change |
|---|---|
| `3c5e589` | Linux-only tests expect the unified engine's correlated finding IDs (verdicts unchanged) |
| `1ca1a80` | Security Lab: Next.js 16.4.3 → 16.4.6 (`npm audit`: 0 production vulnerabilities) |
| `db9df08` | Security Lab: Unified Engine only; `/health` reports `engine_version` and `scanners` |
| `04a3c7c` | VBA: `Run`/`Exec` on an unresolved object is execution when the project creates `WScript.Shell` (closes a bypass found in §5) |
| `c5bb253` | Docs: lowered-verdict counterfactuals; corrected roster-test claim |
| `26ac5da` | `python -m evaluation.demo` and its test |

## 2. Linux CI

| Run | Commit | Result |
|---|---|---|
| [44862798797](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/44862798797) | `b6171a5` (Phase 7) | **failed**: 4 Linux-only tests still expected the retired engine's raw finding IDs. Verdicts were the same. Fixed in `3c5e589`. |
| [44863164387](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/44863164387) | `3c5e589` | passed |
| [44926500680](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/44926500680) | `26ac5da` (release) | passed. Backend on Linux, Python 3.11, non-root, `FM_REQUIRE_LINUX_TESTS=1`: **1314 passed, 2 skipped**; isolation rerun with the `tunl0` fallback device: **31 passed**; production Docker image (non-root, no network): passed; Security Lab (typecheck, lint, build, audit): passed |
| [44863429735](https://github.com/almuthanna1/filesmagic-engine/actions/runs/44863429735) | CE `9ee7e5d` | Full Conversion Engine regression: passed (793 passed, 99 skipped) |
| [44863427714](https://github.com/almuthanna1/filesmagic-engine/actions/runs/44863427714) | CE `9ee7e5d` | Security gate verification: passed (107 passed) |

The Linux-only tests are where strict isolation is proven: user, network and mount namespaces, no
network, the read-only filesystem view, CPU/memory/file limits, the kill on timeout, and
fail-closed behaviour when a control is missing (`tests/test_worker_linux.py`,
`tests/test_security.py`). Locally on Windows: 1273 passed, 43 skipped (the Linux-only tests skip).

The Conversion Engine has one Windows-only failure, `test_cleanup_when_client_disconnects_midway`.
It fails the same way on `main` and passes in Linux CI.

## 3. Staging

Both services are in the "FilesMagic Research" Render workspace: free plan, auto-deploy off. They
use staging-only Ed25519 keys (token `0c984eebe0cedaa2`, receipt `6afc10fef6e8751b`), not the
production keys.

| Service | URL | State |
|---|---|---|
| Security Engine `srv-dc0hh9d9el5s73e58ph0` | https://filesmagic-security-engine-integration.onrender.com | `26ac5da`, `ready_for_conversion: true`, 9 scanners, `SECURITY_ENGINE_REQUIRE_ISOLATION=1` |
| Conversion Engine `srv-dc0hhess728c73a9un30` | https://filesmagic-engine-integration-staging.onrender.com | `9ee7e5d`, production settings (`FILESMAGIC_ENV=production`, `SECURITY_MODE=enforce`, same limits), `SECURITY_ENGINE_COMMIT=26ac5da…` |

Staging defects found and fixed:

1. **Health-check path.** The first deploys of both services timed out. I created them from Git
   Bash, which rewrote `/health` to `/Program Files/Git/health`, so Render's health check got 404.
   Fixed through the API; both services redeployed and went live. This was a mistake in my
   service setup, not an application defect. Production health paths are `/health` (verified).
2. **VBA parameter-passing bypass** (§5). Fixed in `04a3c7c` before the final staging run.

## 4. End to end: frontend → Conversion Engine → Unified Security Engine

Only synthetic, inert fixtures were used, with placeholder commands and `.invalid` hosts. No real
malware was used on any hosted service.

### 4.1 Hosted staging: 32/32 checks passed

| Scenario | Result |
|---|---|
| Clean DOCX → PDF | 200, `X-FilesMagic-Security: SAFE`, output starts `%PDF-` |
| Clean PDF split | 200, ZIP download |
| Repeat request | Scanned again, 200 |
| SUSPICIOUS ×3 (PDF auto-JavaScript with an unrelated attachment; external template; VBA with `vbHide` constant) | 409 `SCAN_CONSENT_REQUIRED` with a consent handle; a forged handle is ignored; consented resubmission gives 200 `ACKNOWLEDGED`; a used handle cannot be reused (409) |
| MALICIOUS ×3 (PDF auto-JavaScript exporting an attachment; AutoOpen → Shell; DDEAUTO cmd.exe) | 422 `SCAN_BLOCKED`, no consent handle. A forged consent handle, `verdict=SAFE` and `authorization=allow` form fields, a fake receipt and an `X-FilesMagic-Security: SAFE` request header all fail with 422 |
| UNABLE_TO_SCAN, eligible reason (truncated DOCX, `DOCUMENT_MALFORMED`) | 409 with consent; after consent the conversion fails cleanly (400 `INVALID_FILE`), with no output |
| UNABLE_TO_SCAN, not eligible (15-byte broken PDF) | Refused (503), no consent offered; a made-up consent is refused. See limitation L1. |
| Conversion fails after a SAFE scan (51 pages, split limit 50) | 413 `TOO_MANY_PAGES` |
| Unsupported input (`.txt`) | 415, rejected before any scan |
| Security Engine directly, no token or a forged token | 401 |
| Security Engine, `engine=reference` | 410 `ENGINE_RETIRED` |

### 4.2 Fault injection: 6/6 passed

These used local Conversion Engines built from the integration branch, against staging.

| Scenario | Result |
|---|---|
| Security Engine unavailable | 503 `SCAN_UNAVAILABLE` after 2 s, no conversion |
| Security Engine hangs | 503 after the 60 s request timeout, no conversion |
| Commit mismatch | 503, log `RECEIPT_WRONG_COMMIT` |
| Roster mismatch (gate with the old 10-scanner roster vs the rebuilt engine) | 503, log `RECEIPT_WRONG_ROSTER` |
| Switch window (`PREVIOUS` also trusted) vs rebuilt engine | 200 |
| `PREVIOUS` equal to `COMMIT` | Conversion Engine refuses to start (`ConfigError`) |

### 4.3 Cutover rehearsal against the old engine: 5/5 passed

For this test the staging Security Engine ran production's `b6774be`, with the staging keys and
`SECURITY_ENGINE_RESEARCH_ENGINES=1`, as in production.

| Gate | Result |
|---|---|
| Today's production gate (old roster, `COMMIT=b6774be`) | Converts SAFE; blocks MALICIOUS |
| Step-1 gate (`COMMIT=26ac5da`, `PREVIOUS=b6774be`) | **Converts SAFE through the old engine; blocks MALICIOUS** |
| New gate without `PREVIOUS` | 503: this is the outage step 1 avoids |

Then the staging Security Engine moved to `26ac5da` with `PREVIOUS` still set (hosted suite 32/32).
`PREVIOUS` was then removed, which is the final state.

### 4.4 Product frontend in a browser

The FilesMagic frontend (`main`, unchanged) ran locally with `NEXT_PUBLIC_SECURITY_SCAN=true`
against the staging Conversion Engine, in the final state with `PREVIOUS` removed. Network
requests went to the staging Conversion Engine only.

- `safe-hyperlink.docx`: "Conversion Complete!", "No known threats detected…", Download link.
- `suspicious-external-template.docx`: "Potential security risk" with the MEDIUM relationship-chain
  evidence, and the buttons "Don't convert" and "I understand the risk, continue". Continuing gave
  "Converted after you chose to continue…" (requests: 409, then 200).
- `malicious-ddeauto.docx`: "Malicious content detected" with both HIGH findings. The only action
  is "Choose a different file", with no way to continue (request: 422).

**The frontend needs no change.** It uses only the gate's codes, verdicts and consent handles,
never scanner names or the roster. The production frontend already sets
`NEXT_PUBLIC_SECURITY_SCAN=true` and `NEXT_PUBLIC_FILESMAGIC_API_BASE_URL=https://api.filesmagic.com`.

## 5. Source audit

| Check | Result | Evidence |
|---|---|---|
| No YARA-X in production | Pass | No `import yara` under `app/`. `yara-x` appears only in `requirements-dev.txt`, as the parity oracle for `tests/test_signatures.py`. It is not in the image. |
| olevba heuristics are not detection authorities | Pass | Only `VBA_Parser.extract_macros` (source extraction) is used; no `analyze_macros` or `detect_*`. Tables are our own (`vba_analysis.py:3,14,185`). |
| Matcher semantics and bounds | Pass | `signatures.py:43-50`: 1000 matches per pattern, 4095-byte regex match, 10 s deadline, 5 evidence items; YARA-compatible `nocase`/`wide`/`within`; parity tested against YARA-X. |
| VBA analysis produces its own evidence | Pass | Findings name module, procedure, line and the resolved call path, e.g. `Module1.AutoOpen -> Module1.Tool (execute: Shell … line 5)`. |
| PDF and Office algorithms function | Pass | Demos in §7 and the guide; the regression suite in CI. |
| No duplicate findings or unintended downgrades | Pass | Correlation removes a reference finding only through an explicit `accounts for scanner:rule` link (`correlate.py:100,394`). `OFFICE_MACRO_AUTOEXEC_EXECUTION` is never removed; correlation never lowers a finding because the source shows no path (the P-code may differ). |
| Incomplete scans are never SAFE | Pass | `app/decision/__init__.py:17-25`: SAFE requires at least one applicable scanner, no failed scanner, complete coverage and no LOW+ finding. The Conversion Engine checks it again (`security_gate.py`: `allow` needs `SAFE`, `complete`, `coverage_complete`). |
| Unsupported techniques documented | Pass | `capstone-technical-guide.md` §2.10 and §10; `regression-report.md` limitations. |

### Lowered VBA verdicts: counterfactual evidence

The rebuild lowered five cases from MALICIOUS to SUSPICIOUS (v05–v08, v14). I didn't assume the old
classifier was wrong. Each case was paired with its dangerous neighbour: the smallest edit that
turns the benign pattern into a real capability.

| Case | Benign pattern → verdict | Attacker neighbour → verdict |
|---|---|---|
| v05 | `style = vbHide` (a constant) → SUSPICIOUS | `Shell "…", vbHide` → MALICIOUS |
| v06 | `Application.Run "Helper"` (harmless macro) → SUSPICIOUS | the run macro calls `Shell` → MALICIOUS |
| v07 | shell32 `SHGetFolderPathA` → SUSPICIOUS | shell32 `ShellExecuteA` → MALICIOUS |
| v08 | user `Sub Shell` showing a message → SUSPICIOUS | user `Sub Shell` wrapping `VBA.Shell` → MALICIOUS |
| v14 | `obj.Run` on an unknown object → SUSPICIOUS | `obj` set to `WScript.Shell` in another procedure → MALICIOUS |
| v14 (gap) | — | `Go CreateObject("WScript.Shell")` then `o.Run` in `Go` → **SUSPICIOUS before `04a3c7c`, MALICIOUS after** |

Every MALICIOUS neighbour carries `office:OFFICE_MACRO_AUTOEXEC_EXECUTION` and
`vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY`. The one gap was a real bypass and is closed.
The analysis is flow-insensitive, so `Run`/`Exec` on an unresolved object now counts as execution
whenever the project creates `WScript.Shell`. Collections are covered too
(`test_a_shell_object_reaching_run_indirectly_is_execution`). A macro file is never SAFE whatever
the VBA analysis decides.

## 6. Security Lab

- The engine selector, the comparison view and their tests were removed (`CompareView.tsx`,
  `lib/compare.ts`). The Lab offers only the Unified Security Engine.
- Kept: the test-file catalog, findings, scanner evidence, evaluation history and the educational
  views. History entries from the retired engine still display, labelled "Original Engine (retired)".
- The status line shows the engine version, commit and nine-scanner roster from `/health`.
- Bug found: the evaluation page called `scanFile` with the old default engine `reference`, so
  every evaluation scan got 410 after Phase 5. Fixed.
- Verified: typecheck, lint, 25 tests, production build, `npm audit` (0 production vulnerabilities),
  CI Lab job.
- Not done: the hosted Lab (`filesmagic-security-lab-staging.vercel.app`) still points to the old
  research staging engine. Redeploying it is separate from the FilesMagic production path.

## 7. Production deployment plan (requires explicit approval)

Current production, read-only check on 2026-11-21:

| Service | Branch | Auto-deploy | Live commit | Relevant settings |
|---|---|---|---|---|
| `filesmagic-security-engine` `srv-db3r5cc9v7es73e57frg` | `main` | **off** | `b6774be` | `REQUIRE_ISOLATION=1`, `RESEARCH_ENGINES=1` (ignored by the new release, harmless), receipt key `df3ee2f1a3c368c6`, health `/health`, `ready_for_conversion: true` |
| `filesmagic-engine` `srv-da5qcv0u01pc73853ajg` | `main` | **on** | `482e724` | `SECURITY_MODE=enforce`, `SECURITY_ENGINE_COMMIT=b6774be…`, `SECURITY_ENGINE_URL=https://filesmagic-security-engine.onrender.com`, `/health` 200 |
| `filesmagic-frontend` (static) | `main` | on | — | `NEXT_PUBLIC_SECURITY_SCAN=true`, API `https://api.filesmagic.com` |

The keys stay the same, and no new secret is needed.

### Order

1. **Conversion Engine first, trusting both releases.**
   - In the Render dashboard for `filesmagic-engine`, set `SECURITY_ENGINE_COMMIT=26ac5da1bc5e782ff4e934cdc2fdf6f5bfa95038` and `SECURITY_ENGINE_PREVIOUS_COMMIT=b6774bea199f13170a4dfb144048f7d63f59b859` with **"Save only"**, not "Save and deploy". Production `482e724` does not know `PREVIOUS`; redeploying it with only the new `COMMIT` would refuse every scan.
   - Fast-forward `main` to `9ee7e5d`. Auto-deploy then deploys the new gate with both variables.
   - Verify `/health`, then convert an inert SAFE file through `https://api.filesmagic.com`. The old engine is still answering, under `PREVIOUS`.
2. **Security Engine.**
   - Fast-forward `main` to `26ac5da` (no merge commit, no squash).
   - Manual deploy of commit `26ac5da` (auto-deploy is off).
   - Verify `/health`: `commit=26ac5da…`, 9 `scanners`, `ready_for_conversion: true`, `receipt_key_id=df3ee2f1a3c368c6`.
3. **Verify** through the production site, with inert fixtures only (`e2e-fixtures`): one SAFE conversion, one consent flow, one MALICIOUS block. Watch the Conversion Engine logs for `RECEIPT_` errors.
4. **Close the window.** Delete `SECURITY_ENGINE_PREVIOUS_COMMIT` and redeploy `filesmagic-engine`. Repeat one SAFE conversion. Later, a small commit can remove `LEGACY_ROSTER` and the setting.

There is no point where the gate trusts no running engine: before step 2 the old engine is trusted
under `PREVIOUS`, and after step 2 the new one under `COMMIT`. Step 2's deploy goes live once
`/health` passes, so the instance switch itself is the only moment of risk, and both commits are
accepted throughout it.

### Rollback

| After | Rollback | Outage? |
|---|---|---|
| Step 1 | Render rollback of `filesmagic-engine` to `482e724` and `SECURITY_ENGINE_COMMIT=b6774be…`, or keep `9ee7e5d` (it still accepts `b6774be`) | No |
| Step 2 | Render rollback of `filesmagic-security-engine` to `b6774be`. The gate still trusts it under `PREVIOUS`. | No. **This is why `PREVIOUS` stays until step 3 passes.** |
| Step 4 | First set `PREVIOUS=b6774be…` again and redeploy the Conversion Engine, then roll back the Security Engine | No, if done in that order |
| Emergency | `SECURITY_MODE=report` stops enforcement but keeps scanning and logging. It is weaker and must be temporary. | — |

Git rollback: `baseline/pre-custom-rebuild` tags `b6774be`; `main` of both repositories can be reset to
the commits in §1.

## 8. Remaining limitations

- **L1.** A PDF that pypdf cannot open makes `pdf-integrity` fail as "unexpected", which gives
  `SCANNER_INTERNAL_ERROR` (operational, never receipted). The gate therefore answers 503 "try
  again later" instead of "this file is damaged". It fails closed (no conversion, no consent).
  Production has the same behaviour today (`docs/security-integration-v1-readiness.md`).
  Reclassifying it as `DOCUMENT_MALFORMED` would make such files consent-eligible, so it was
  deliberately not changed.
- **L2.** VBA is analysed from source only: no P-code (stomping), XLM by function name only, no data
  flow through branches or arguments. The new fail-closed `Run`/`Exec` rule can make a project that
  also uses an unrelated `.Run` MALICIOUS.
- **L3.** The worker isolates with Linux namespaces and limits; it is not a VM sandbox. Kernel and
  native-parser exploits are out of scope. On Render, egress from the API process is not restricted.
- **L4.** No real malware corpus was analysed, so no detection rate is claimed. Benign corpora
  contain no VBA.
- **L5.** Staging runs on the free plan (cold starts of 30–60 s). Production Security Engine runs on
  `0.5c-512mb`; the rebuilt engine passed staging at 512 MB.
- **L6.** The hosted Security Lab has not been redeployed (§6).

## 9. GO / NO-GO

**GO, conditional on your explicit approval.** All required scenarios pass on staging and in CI. The
cutover rehearsal shows no outage window, and every step has a rollback that causes no outage.
Conditions: fast-forward merges only, and the order in §7.

## 10. Clean-up after the decision

- Delete the two staging services, or keep them for the demonstration (free plan, no cost).
- Delete the local staging keys (scratchpad `staging-keys/`). They are staging-only and were never
  committed, printed or passed on a command line.
