# Integration plan: custom Security Engine → Conversion Engine and frontend

**Status: plan only.** Nothing in `filesmagic-engine` or `FilesMagic-frontend` has been changed or
deployed. Both were inspected read-only. Execution needs explicit authorization. Facts below are
cited by file and line so they can be re-checked.

## 1. What changed in the Security Engine's contract

| Item | Before (b6774be) | After (feature branch) | Conversion Engine impact |
|---|---|---|---|
| `/scan?engine=unified` | Required `SECURITY_ENGINE_RESEARCH_ENGINES=1` | Always available, and the default | None. The gate already sends `engine=unified` (`security_gate.py:207`). |
| `/scan?engine=reference` | The original 4-scanner engine | **410 `ENGINE_RETIRED`** | None. The gate never sends it. |
| Receipt `engine` | `"unified"` | `"unified"` | None. |
| Receipt `scanners` (sorted roster) | 10 names, including `yara-x` and `yara-x-engine` | 9 names: `custom, office, ooxml-links, pdf, pdf-chains, pdf-integrity, signatures, vba-chains, word-fields` | **Required change.** The `ROSTER` pin. |
| Receipt `commit` | Pinned | The new release commit | **Required change.** `SECURITY_ENGINE_COMMIT`. |
| `ruleset_sha256`, `scanner_versions` | YARA rules hash; included yara-x | The signature rule set's hash; parsers only | None. The gate does not verify them (`verify_receipt`, `security_gate.py:286-335`). |
| Verdicts, `authorization`, `override_eligible`, reasons | | Unchanged | None. |
| `/health` `ready_for_conversion`, `commit` | | Same condition and fields (`app/main.py:149`) | None. The wake check reads both (`security_gate.py:261-263`). |
| Verdict outcomes | | 5 synthetic VBA cases MALICIOUS → SUSPICIOUS ([regression-report.md](regression-report.md) §2) | Behaviour. Those files now reach the consent flow instead of being blocked. |

## 2. Conversion Engine (`filesmagic-engine`)

### Required code change (one)

Update `ROSTER` in `app/security_gate.py:79-82`:

```python
ROSTER = [
    "custom", "office", "ooxml-links", "pdf", "pdf-chains", "pdf-integrity",
    "signatures", "vba-chains", "word-fields",
]
```

Set `SECURITY_ENGINE_COMMIT` to the merged Security Engine commit, in the same release. If either
the roster or the commit is out of step, every receipt fails (`RECEIPT_WRONG_ROSTER` or
`RECEIPT_WRONG_COMMIT`), so every conversion is refused. This fails closed, but it is an outage.
The order of operations is in §4.

The old roster appears in exactly two files (searched read-only for `yara-x-engine`): this one,
and `docs/SECURITY-GATE.md`, which should be updated too. Correction (Phase 8): one Conversion
Engine test did hard-code it (`tests/test_security_gate.py`, `len(gate.ROSTER) == 10`); the
integration branch updates it.
`docs/SECURITY-GATE.md:216-217` also lists `SECURITY_ENGINE_RESEARCH_ENGINES` and
`SECURITY_ENGINE_PUBLIC_UNIFIED_ONLY` as required Security Engine settings. The Security Engine no
longer reads either one; leaving them set is harmless.

### Behaviour to re-verify, with no code change expected

| Area | Current gate behaviour | What to verify after the change |
|---|---|---|
| API compatibility | POSTs raw bytes with a signed scan token to `/scan?engine=unified` | The receipt verifies end to end against a staging engine at the new commit |
| Engine selection | The constant `ENGINE = "unified"` | `RECEIPT_WRONG_ENGINE` is never raised |
| Scan authorization | Token audience `filesmagic-security-engine/scan`; file-bound `sha256`/`size`/`token_jti` | Unchanged. Run the existing gate tests. |
| Four verdicts | `allow` → convert; `consent_required` (SUSPICIOUS, or UNABLE_TO_SCAN with eligible reasons) → 409 `SCAN_CONSENT_REQUIRED` + consent handle; `deny` → refuse; MALICIOUS must be `deny` (`security_gate.py:331`) | One staging file per verdict, using the inert fixtures in `evaluation/cases` and `evaluation/vba_cases` |
| Consent and overrides | `override_eligible` must equal `authorization == "consent_required"` (`:377`) | Unchanged in the engine (`app/decision`) |
| Failure handling | Receipt errors refuse; only upstream 429 is retried | Unchanged |
| Timeouts | 60 s request timeout; 429 back-off 2/5/10/15 s within a 50 s budget, below the 120 s request limit (`:85-91`) | The rebuild's in-worker time is about 3.5 ms median. Wall time is dominated by worker start-up (~0.6 s locally), so the budget is unchanged. |
| Conversion blocking | No receipt, or `deny` → no conversion | Unchanged |
| Recovery and retry | Health wake requires `ready_for_conversion` and a matching `commit` | Wake against staging at the new commit |

## 3. Frontends

### Product frontend (`FilesMagic-frontend`): no change expected

The product frontend talks only to the Conversion Engine; it never calls the Security Engine or
names an engine. It already handles everything the plan covers:

- the four verdicts, with labels in `src/components/converter/SecurityResult.tsx:54-58`;
- the consent flow (`consentsFor`);
- blocking MALICIOUS and non-eligible results, with no way to continue (`:277`);
- the upload, progress, download and error paths (`src/lib/conversionService.ts`,
  `src/hooks/useConversionRunner.ts`, `src/lib/conversionErrors.ts`).

Things to verify, not change:

- Findings now carry `scanner: "signatures"` instead of `"yara-x"`. A read-only search of `src/`
  found no reference to `yara-x`.
- The SUSPICIOUS warning and consent path is exercised by a macro file that used to be MALICIOUS
  (VBA case v05 or v06).
- MALICIOUS blocking is exercised by v01; UNABLE_TO_SCAN by a malformed PDF.

### Security Engine Lab UI (`Security Engine/frontend`): needs a small change

This UI is not the product, but it is part of this repository. It was deliberately not changed
during the rebuild, so it is out of date:

- `lib/api.ts:11` still lists `ENGINES = ["reference", "unified"]`, with the label "Original
  Engine".
- `lib/api.ts:187-188`: if `/health` cannot be read, it "offers the original engine only". That
  engine now returns 410. The API refuses explicitly, so this is not unsafe, but it is a dead end
  for the user.

The proposed change, which needs your authorization because it is a frontend: set `ENGINES` to
`["unified"]`, remove the reference fallback, and show a 410 `ENGINE_RETIRED` response as "engine
retired". Then update its tests and the comments at `lib/api.ts:9-10`.

## 4. Rollout order (each step needs your explicit go-ahead)

1. Review and merge `feature/custom-malware-detection-rebuild`. Record its 40-character commit.
2. Deploy it to the Security Engine **staging** service, with Linux isolation on. Run the Linux
   isolation tests (`tests/test_worker_linux.py`) there, because they were skipped on Windows.
3. On a Conversion Engine branch, update `ROSTER`, `SECURITY_ENGINE_COMMIT` (staging) and the
   docs. Run its test suite against staging: one file per verdict, consent, timeout and retry.
4. Production: deploy the Security Engine first. The current Conversion Engine then refuses
   receipts (wrong commit and roster) until step 5, so do steps 4 and 5 back to back, in a
   low-traffic window. The alternative is to run both engine versions behind separate URLs during
   the switch.
5. Deploy the Conversion Engine with the new pins. Then smoke-test production: one SAFE file, one
   SUSPICIOUS file with consent, one MALICIOUS block.
6. Lab UI change (§3), whenever convenient; it is independent of steps 4 and 5.

**Rollback.** Redeploy the previous Security Engine commit and the previous Conversion Engine
pins together. The old roster and commit pins are in git history.

## 5. Known gaps to accept or close before production

- Worker memory has not been measured. The Linux CI rlimits bound it, but there is no number
  ([regression-report.md](regression-report.md) §7).
- The benign corpora contain no VBA, so the false-positive behaviour on real macro documents is
  untested.
- A PDF that pypdf cannot open is classified as `SCANNER_INTERNAL_ERROR` (deny), not as a document
  reason. This is documented and deferred (`docs/security-integration-v1-readiness.md:136`).
