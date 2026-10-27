# Capstone presentation outline (8-10 slides, about 15 minutes with discussion)

**For:** the next meeting with Dr. Nur Imtiazul Haque. **Source of every number:**
[capstone-evidence-package.md](capstone-evidence-package.md). Say "demonstrated", "reported"
or "planned" deliberately; the research is **not** finished.

## 1. Title and status

- FilesMagic Security Engine: an isolated, explainable document security gate.
- NIU CSCI 499 Honors Capstone; Almuthanna Shihab; supervisor Dr. Haque.
- Status line: implementation and benign/synthetic staging validation done, on a separate
  research staging deployment (not integrated into the customer-facing conversion pipeline).
  Labelled real-world evaluation not yet conducted; it is waiting on approvals.

## 2. Problem and research questions

- A document converter parses untrusted files: macros, PDF actions and malformed structure.
- Goal: a static gate that explains its findings and never passes an unscanned file.
- Open questions: detection rate on independently confirmed malware, false positives on
  legitimate active documents, coverage, and the cost of isolation.

## 3. Architecture and trust boundaries

- One diagram (evidence package §3): browser → Vercel Lab (signing key) → 120 s, single-use,
  hash-bound token → direct upload to Render → fresh worker → YARA-X / Office / PDF → verdict.
- Each boundary holds only what it needs. Render has only the public key, and the file never
  passes through Vercel.

## 4. Detection and verdicts

- Three layers with their known blind spots (evidence package §4).
- Ordered rules: HIGH/CRITICAL → MALICIOUS; LOW/MEDIUM → SUSPICIOUS; failure → UNABLE_TO_SCAN;
  else SAFE.
- SAFE ≠ harmless; UNABLE_TO_SCAN ≠ SAFE.
- Findings outrank failures, so a SUSPICIOUS or MALICIOUS verdict can come from an incomplete
  analysis. Gate rule: only SAFE with `complete=true` (and no missing isolation control) may
  pass. Incomplete analysis never authorizes conversion.

## 5. Containment and fail-closed design

- Per-scan worker: empty environment, timeout, rlimits, user and network namespace, network
  verification without sending packets, all capabilities dropped, audit hook.
- Strict mode: the worker refuses to scan unless every required control holds, and reports
  `isolation_missing`.
- Honest scope: not a sandbox. Shared user, container and kernel; the API keeps internet access.

## 6. Case study: the Render `tunl0` finding

- The strict deployment refused every benign scan, which is fail-closed working as designed.
- Log-only diagnostics found the kernel's IP-in-IP fallback device: down, no address, no route.
- Fix: accept exactly that device after field-by-field checks, and drop capabilities so it
  can't be changed later.
- Exercised in Linux CI against the real kernel module (blocked egress, capabilities that
  cannot be regained). On Render, observed as the worker's own kernel read-backs
  (`isolation_missing=[]`), not probed independently.
- Lesson: precise invariants, and evidence from the target environment.

## 7. Evidence (keep runs separate)

- **CI** ([40381320558](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/40381320558)):
  368 Linux tests passed, plus a separate 27-test rerun with a real `tunl0`. All three jobs
  green.
- **Staging (Phase C4):** 19/19 acceptance checks; 16/16 synthetic fixtures matched their
  intended verdicts.
- **Hosted (C7D/C7E):** harmless DOCX and PDF `SAFE`. The inert synthetic Launch-indicator test
  PDF got `MALICIOUS`, the engine's intended verdict for that indicator; it is not a malware
  sample or ground truth. No missing controls; about 6-7 s per scan on Render Free, dominated by
  worker start-up.
- Caveat on the slide: the fixtures test the rules, and CI proves kernel behaviour. On Render,
  isolation is reported by the worker itself.

## 8. Limitations and validity

- Not yet measured: accuracy, false-positive rate, false-negative rate.
- Fixture expectations come from the same rules, so they are not independent labels.
- Self-reported isolation on Render; shared kernel; API egress; one-time checks.
- Future bias risks: antivirus-consensus labels, popular-family skew, temporal leakage.

## 9. Proposed evaluation

- Offline isolated VM only. The harness calls the API in process, but every sample still runs
  in a separate worker. The harness must first be made strict-aware: record isolation and
  require strict mode.
- Ground truth fixed before scanning: curated repository plus at
  least five vendor detections or a published analysis; benign from trusted publishers with
  clean hash lookups.
- Frozen engine and rule-set hash; time-aware holdout; reporting per format and per family.
- Metrics: confusion table, recall, false-positive rate, precision (with prevalence caveat),
  coverage failures, latency, memory, 95% Wilson intervals.

## 10. Decisions needed from Dr. Haque

- Approve, or revise, the sample-handling procedure.
- Identify the NIU office for the IT security / research-compliance determination.
- Agree on the dataset sources, size and metrics.
- Decide whether hosted analysis is in scope. If so, it needs stronger containment and Render's
  written authorization first; otherwise the study stays offline.
- Until then, genuine malware stays blocked.
