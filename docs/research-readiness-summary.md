# Research readiness summary for supervisor review

**FilesMagic Security Engine · NIU CSCI 499 Honors Capstone · Almuthanna Shihab**
**For:** Dr. Nur Imtiazul Haque · **Status date:** 2026-10-27

**Bottom line.** The offline evaluation environment is **technically ready** for a small,
supervised evaluation. That readiness is **not authorization**: no genuine malware has been
acquired or handled, and none will be until the approvals in Section 6 are recorded.

Details and evidence:
[capstone-evidence-package.md](capstone-evidence-package.md),
[offline-vm-validation-c9-2.md](offline-vm-validation-c9-2.md),
[malware-sample-handling-procedure.md](malware-sample-handling-procedure.md) (proposal) and
[evaluation/README.md](../evaluation/README.md).

## 1. What has been implemented

- **The engine.** A document security gate: YARA-X signatures plus Office and PDF structural
  analysis, with explainable verdicts (`SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNABLE_TO_SCAN`).
- **Per-scan worker controls.** Each scan runs in a fresh worker process:
  - an empty environment;
  - its own user and network namespace, verified to contain no usable route;
  - every Linux capability dropped, with no-new-privileges and locked securebits;
  - resource limits and an in-process audit hook.

  In **strict mode** the worker refuses to scan unless every required control is confirmed.
- **The offline evaluation harness.** Before reading any sample it proves strict isolation with a
  harmless preflight. It records the isolation evidence for every sample, separates isolation
  failures from parser failures, and stops the run if isolation is lost. Ground truth is kept
  separate from the engine's verdicts.

## 2. What Linux CI validated (GitHub Actions, Ubuntu 24.04)

- **Latest run:**
  [40447531705](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/40447531705)
  at commit `b1a6946`.
  - 386 backend tests passed, 0 failed, 0 skipped.
  - A separate run with the Render-style `tunl0` device reproduced: 28 passed.
- **What it proves on a real kernel:**
  - outbound connections are blocked inside the worker's namespace;
  - capabilities can't be regained after the drop;
  - strict mode fails closed whenever any control is missing;
  - the harness's strict path works.

## 3. What was validated in the actual offline VM

- **VM:** Ubuntu 24.04.5 LTS, kernel 7.0.0-38. No network adapters, USB, audio, clipboard or shared
  folders.
- **Installation:** the engine at commit `b1a6946` with pinned dependencies, running on a
  root-owned, dedicated Python 3.11.18.
- **AppArmor:** Ubuntu's default policy blocked the worker's capability drop, which strict mode
  correctly refused. A narrowly scoped AppArmor profile, **enforcing** and attached only to that
  interpreter, now allows it. The profile denies every capability except the two the worker needs,
  and denies TCP sockets.
- **Strict preflight:** passed twice, including after a reboot. SAFE, complete, every required
  control true, `isolation_missing=[]`.
- **Capability drop:** after the drop, all five capability sets were empty, with no-new-privileges
  and locked securebits.
- **Small evaluation of four inert files:**

  | File | Result |
  |---|---|
  | Harmless DOCX | SAFE |
  | Harmless PDF | SAFE |
  | Inert synthetic `/Launch` indicator test | MALICIOUS (the engine's intended verdict on a constructed indicator; not malware or ground truth) |
  | Malformed PDF | UNABLE_TO_SCAN, classified as a parser failure |

  The exports contained metadata only.
- **Linux tests in the VM:** only the worker and evaluation test files were run (65 tests):
  **61 passed, 4 failed**. This is not a full pass. The failures are:
  - two tests that assume the host itself is networked (`test_network_verification_detects_the_host_network`,
    `test_diagnostics_read_real_interface_state_in_the_host_namespace`);
  - two tests that expect weaker restrictions than the profile enforces: TCP sockets are denied
    (`EACCES` instead of `ENETUNREACH`), and network-admin is denied even before the drop.

  None is an engine defect. Test corrections that keep each test's purpose are proposed but not
  applied. The rest of the backend suite was validated in Linux CI (Section 2), not in the VM.

## 4. What remains unverified

- Detection performance on independently labelled real documents. **No accuracy, false-positive
  or false-negative rate has been measured.**
- Worker memory use. Only the harness process's memory is recorded.
- A reduced, study-only AppArmor profile without the test allowances. It is proposed and needs
  re-validation.
- Host disk encryption (BitLocker), required by the handling procedure. It has not yet been
  checked.

## 5. Why the VM is not an absolute security boundary

- **Shared guest:** the worker shares the guest kernel and the researcher's guest account.
- **Shared guest user:** the harness, its workers and the tests run under one guest account and
  one AppArmor profile.
  - The worker establishes its isolation before it reads the document: namespace, capability drop,
    resource limits, then the audit hook.
  - A native-code exploit in a parser would still keep the permissions that remain after those
    controls. It could read everything the profile allows, including other samples. It could also
    delete, rename or truncate files, or create empty ones, in the results folder and `/tmp`,
    where the profile allows writing.
- **`RLIMIT_FSIZE=0` is only a resource limit.** It stops a process from growing any regular file
  beyond 0 bytes. It does not stop deleting, renaming or truncating files, creating empty files,
  or overwriting bytes within an existing file's size. It is not a filesystem security boundary.
- **`CAP_SYS_ADMIN` before the drop:** between creating its namespaces and dropping its
  capabilities, the worker briefly holds `CAP_SYS_ADMIN` and `CAP_SETPCAP` inside those namespaces.
  This happens before it reads the document; AppArmor still denies mounting and every other
  capability.
- **Hypervisor:** VirtualBox runs under the Windows hypervisor, and hypervisor escapes are out of
  scope.
- **Mitigations:** the VM has no network, no shared folders and no clipboard; samples would never
  leave it; snapshots allow a clean rollback after every session. A further worker-only
  restriction is proposed.

## 6. Approvals and determinations needed before any genuine malware

| # | Requirement | Status |
|---|---|---|
| 1 | Dr. Haque's approval to proceed with the study (supervisor approval) | **Pending** |
| 2 | Approval of the sample-handling procedure (sources, storage, deletion, incident response) | **Pending** (document is a proposal) |
| 3 | NIU IT security / research-compliance determination, and any required approval | **Pending**; office to be identified |
| 4 | Dataset approval: sources, labelling rules, size, time split and metrics (Section 7) | **Pending** (design proposed only) |
| 5 | Acceptance of each sample source's terms (e.g. MalwareBazaar) | **Pending** |
| 6 | Host disk-encryption (BitLocker) verification, required by the handling procedure | **Pending** (not yet checked) |
| 7 | Approved procedure for bringing research samples into the offline VM and exporting metadata-only results (method, integrity checks, who performs it, how the VM stays offline) | **Pending**. Not finalized, and no mechanism implemented; the VM has no network, shared folders, USB or clipboard |
| 8 | Hosted (Render) analysis | **Out of scope.** Render's written authorization and stronger containment would be required first; not requested |

**Technical readiness is not approval.** The VM results above do not authorize handling genuine
malware. Items 1-7 must all be resolved and recorded first.

## 7. Proposed independently labelled methodology (planned, not results)

- **Ground truth fixed before scanning.**
  - `MALICIOUS`: a curated repository with a family attribution, **and** at least five
    independent vendor detections or a published analysis.
  - `BENIGN`: a trustworthy publisher, **and** no detection in a hash lookup.
  - Everything else is `EXCLUDED`.
  - Hash lookups only; samples are never uploaded to third-party services.
- **Design.**
  - Recorded provenance and SHA-256 for every sample.
  - Duplicates removed.
  - A development/holdout split that is time-aware.
  - Results reported per format and per malware family.
  - A frozen engine commit and rule-set hash for each run.
- **Metrics.**
  - The full ground-truth-by-verdict table, under three views: conversion gate, fail-closed and
    conviction-only.
  - Recall, false-positive rate, and precision with a prevalence caveat.
  - Coverage failures and latency.
  - 95% Wilson intervals.
- **Environment.** This offline VM only. Strict preflight must pass before every session; restore
  the snapshot after every session.

## 8. Why genuine-malware testing has not started

Requirements 1-7 in Section 6 are not yet recorded or finalized, and the handling procedure is
still a proposal.
The project's rule is that technical readiness never substitutes for authorization.

## 9. Decisions requested

1. Approve, revise or reject the sample-handling procedure.
2. Identify the NIU office for the required determination.
3. Agree on sources, dataset size and metrics.
4. Confirm the study stays offline in this VM, with hosted analysis out of scope.
5. Approve the proposed clean-ups: the test corrections, a study-only AppArmor profile, a separate
   worker profile, and removal of leftover files.
