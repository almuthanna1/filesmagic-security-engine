# Capstone presentation outline (8-10 slides, about 15 minutes with discussion)

**For:** the next meeting with Dr. Nur Imtiazul Haque. **Source of every number:**
[capstone-evidence-package.md](capstone-evidence-package.md). Say "demonstrated", "reported"
or "planned" deliberately; the research is **not** finished.

**Oct 30 meeting update.** The built deck has 12 main slides and 4 appendix screenshot slides,
saved outside the repository with its build script and screenshots. Compared with this outline
it adds three things:

- **The intended security-first architecture**
  ([security-first-architecture.md](security-first-architecture.md)). The Security Engine is the
  entry point. It always returns a verdict and explanation, and calls the independent Conversion
  Engine itself only for a complete, SAFE scan with every mandatory control passed. The
  Conversion Engine stays unchanged, with no hook inside its routes. It is shown as **intended
  design, not implemented**.
- **What runs in VirtualBox today:** the standalone Security Engine in the offline VM. The
  FilesMagic conversion app is not in the VM.
- **The C10 experiment** ([c10-docx-external-template-experiment.md](c10-docx-external-template-experiment.md)):
  - only the Office scanner flags the harmless synthetic external-template test file;
  - YARA-X has no finding for this technique under the current rules: there is no matching rule,
    and compression hides the text. This is not a general detection result;
  - PDF analysis is not applicable;
  - verdicts: control SAFE, indicator SUSPICIOUS, 5 of 5 strict runs.

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
- **Intended next architecture (not implemented):** the frontend uploads to the Security Engine,
  which always returns a verdict and explanation. Only for SAFE + complete + all mandatory
  controls passed does it call the independent Conversion Engine, with the same SHA-256-verified
  bytes and trusted service authentication. Conversion results are reported separately, and no
  conversion request may bypass the scan.

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
  in a separate worker. The harness now refuses to start without a passing strict-isolation
  preflight, records isolation per sample, and stops if isolation is lost. (Implemented locally;
  Linux CI and the VM preflight are still to come.)
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
