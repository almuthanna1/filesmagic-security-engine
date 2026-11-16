# FilesMagic Security Engine
## Capstone Development History and Research Journal

**Northern Illinois University | CSCI 499 Honors Capstone**  
**Student:** Almuthanna Shihab  
**Faculty mentor:** Dr. Nur Imtiazul Haque  
**Period covered:** September 2026 through November 14, 2026  
**Document status:** Living draft v0.2, created November 13, 2026; updated November 14, 2026  
**Repository:** https://github.com/almuthanna1/filesmagic-security-engine  
**Current research branch:** feature/custom-unified-engine-nov18  
**Important distinction:** This document is a chronological account of *research and engineering work*. It is not a claim that the Security Engine is integrated with, or approved to protect, the production FilesMagic Conversion Engine.

> **Reading guide.** “Implemented” describes code that exists. “Tested” describes a documented test in a stated environment. “Measured” describes preserved numerical evidence. “Proposed” describes future work. “Blocked” identifies unfulfilled prerequisites. Numbers from different experiments and datasets are never added into one accuracy statistic. A scanner verdict describes the rules in force; it is not a ground-truth label.

### Executive overview

The capstone began with an operational problem: FilesMagic converts documents uploaded by users, and a conversion service inevitably exposes complex file parsers to input it cannot trust. In the earliest mentor discussions, the student proposed a pre-conversion malware-analysis component to reduce that exposure. The initial vision was broader than the eventual prototype, including ClamAV, signature matching, Office and PDF analysis. The project evolved into an independently deployable FastAPI security service with a browser-based research Lab, three original baseline scanner layers, a custom structural scanner, and subsequently a separate custom unified research engine.

The research challenge was never merely “find a suspicious string.” It became a sequence of narrower questions: Can the system describe *why* a document is risky? Can untrusted parsing run within measurable containment? Can independent layers disagree without producing dishonest conclusions? Can a custom engine reduce selected false positives without suppressing real indicators? Can the evidence be reproduced on a disconnected Linux VM? Finally, can the platform distinguish a scanner that *finished* from a document it has *fully covered*?

By November 9, the unified research engine had a frozen, reproducible offline evaluation: 57 inputs scanned through two engine configurations, 114 of 114 expected results, 11 of 11 contribution checks, and strict isolation on every scan. The 1,004-test VM suite had 993 passes and 11 measured environment skips, while Linux CI passed all 1,004 tests. This established a standalone research milestone, not malware-detection accuracy or production readiness. A later November 13 external corpus revealed important new gaps: eight attachment-related conservative warnings, a correctly rejected malformed PDF, and three particularly important SAFE results on unsupported, repaired, or partially inspected documents. These findings shaped a November 14, post-freeze PDF coverage remediation: the encrypted and damaged-data qpdf cases were re-scanned in the research-only hosted Lab after targeted changes. Both behaved as intended, with the damaged file now returning UNABLE_TO_SCAN rather than SAFE. Other external-validation questions and production conversion authorization remain open.

---

## 1. Why the project began

### 1.1 The real FilesMagic problem

FilesMagic is a document conversion website and backend. In an early September 2026 discussion with the mentor, the product was described as having roughly 60–65 users. That usage made the exposure to untrusted uploaded files concrete rather than hypothetical. A PDF or Office document may contain macros, active PDF actions, external templates, embedded files, malformed cross-references, compressed content, or unusual parser behavior. Conversion often requires decoding or transforming those structures.

The project objective became a separate security analysis layer that would inspect a file *before* the independent conversion backend processes it. A scanner that says “SAFE” is not an antivirus guarantee. At best, it has successfully checked for its known indicators and reported its limits. The long-term design is therefore a **fail-closed security gate**, not just an informational virus score.

### 1.2 The initial research proposal and mentor direction

The September 4 discussion established interest in malicious Office macro detection, independent evaluation, open-source work, and documented capstone research. By early October, the plan called for a separate repository/service using ClamAV, YARA-X, oletools, and a PDF library. The chosen direction was independent rather than modifying the conversion service prematurely.

The mentor repeatedly emphasized two requirements that influenced the project: **explain original intellectual contributions** instead of claiming third-party libraries as original work, and **design evidence that distinguishes detections from false positives and untested assumptions**. The November 6 meeting sharpened this further: define limited, defensible malicious-document *techniques*; compare existing and custom tools on them; keep a learning record; and support the November 18 poster with figures and measured outcomes.

**Source trail:** [Approved custom research plan](custom-engine-approved-plan-2026-11-06.md), [security-first architecture](security-first-architecture.md), and November 6 mentor meeting notes/transcript retained with the student's working materials. The exact original September proposal text still needs to be attached to this journal as a historical source.

---

## 2. Dated development timeline

| Date | Milestone | What changed or was learned | Primary evidence |
|---|---|---|---|
| Early September | Capstone idea and mentor discussion | Document malware detection connected to the actual FilesMagic conversion threat model. | Earlier mentor correspondence; original proposal to archive |
| October 5 | Independent service direction | Proposed ClamAV, YARA-X, OLE and PDF analysis; isolated lab and separate service. | Planning discussion; repository initialized October 8 |
| October 8 | First API and Lab | Initialized FastAPI, scanner interfaces, decision model and Security Lab UI. | Commits [620764c](https://github.com/almuthanna1/filesmagic-security-engine/commit/620764c37d), [1d5e98f](https://github.com/almuthanna1/filesmagic-security-engine/commit/1d5e98fe24), [ca7a8da](https://github.com/almuthanna1/filesmagic-security-engine/commit/ca7a8da98c) |
| October 9 | Three baseline detection layers | Replaced planned ClamAV with lightweight YARA-X; built Office and PDF structural scanners; added evaluation harness. | Commits [81bfc93](https://github.com/almuthanna1/filesmagic-security-engine/commit/81bfc938c3), [e982a61](https://github.com/almuthanna1/filesmagic-security-engine/commit/e982a619e7), [0b0494f](https://github.com/almuthanna1/filesmagic-security-engine/commit/0b0494f3ff), [dd3863f](https://github.com/almuthanna1/filesmagic-security-engine/commit/dd3863f761) |
| October 10 | Reproducible build/test baseline | Synthetic test library and first GitHub Actions pytest checks. | [Workflow](../.github/workflows/security-engine-tests.yml), commits b999941 and e6fdbd4 |
| October 23–26 | Security redesign and research staging | Audited confirmed upload/auth/process issues; introduced signed per-file scan tokens, raw bounded input, isolated workers, concurrency control, and strict isolation. | [Malware research readiness](malware-research-readiness.md), [capstone evidence package](capstone-evidence-package.md) |
| October 26 | Hosted acceptance and tunl0 correction | 19/19 staged acceptance checks and 16/16 inert fixtures passed; Render's inert tunl0 required a precisely bounded isolation exception. | [Phase C4 results](phase-c4-test-results.md) |
| October 27–28 | Offline VM and controlled techniques | Offline Ubuntu/AppArmor validated; external Word template and inert VBA-storage experiments; intended architecture documented. | [Offline VM C9.2](offline-vm-validation-c9-2.md), [C10](c10-docx-external-template-experiment.md), [C10.1](c10-1-vba-project-presence-experiment.md) |
| November 3–4 | Custom structural detector and evaluation transport | Added C1 PDF name escapes, C4–C6 OOXML checks, shared scanner errors and per-scanner duration; prepared deterministic read-only ISO and EICAR/Didier study. | Commits 4ad703c, 3a497b6, edf1ed8, 940e710, c8bf8dd; [evaluation notes](eicar-didier-evaluation.md) |
| November 6 | Custom unified engine research begins | Mentor-approved narrow hypotheses; controlled case matrix; contextual PDF action chains, correlation, VBA call graph and OOXML activation graph. | [Approved plan](custom-engine-approved-plan-2026-11-06.md), [research log](custom-engine-research-log.md) |
| November 7 | Research comparison interface and poster figures | Reference vs unified engine in same Lab, freeze at 1668326, generation of first poster figures. | Commits 145ce63, a927da9; [poster figures](poster/figures/comparison.md) |
| November 8 | Real-world benign false positives | 29-file benign review revealed four warnings; unified-only evidence-constrained corrections reduced that set to one; later security review hardened the corrections. | [Benign corpus evidence](evidence/benign-corpus/README.md) |
| November 9 | C7 and final offline freeze | Added Word field-code analysis; fixed VM test-environment observations; final 114/114 expected scan outcomes and 11/11 contributions at eda2a08. | [Readiness report](engine-readiness-report.md), [frozen evidence](evidence/final-eda2a08-run3/README.md) |
| November 10–11 | PDF accuracy and Content Credentials research | Pre-registered PDF attachment accuracy, resolved the empty-attachment-name-tree false positive, and started a bounded C2PA manifest verifier study. | [PDF preregistration](pdf-accuracy-preregistration.md), [PDF evidence](evidence/pdf-accuracy-c24c52c/summary.md), [C2PA preregistration](c2pa-accuracy-preregistration.md) |
| November 12–13 | Public research Lab refinement | Added sourced downloads, retained scan history, full evidence exports, unified-only public controls and an in-page uploader. | Merged PRs [#9](https://github.com/almuthanna1/filesmagic-security-engine/pull/9) through [#13](https://github.com/almuthanna1/filesmagic-security-engine/pull/13) |
| November 13 | External validation and honest readiness reassessment | 32-case catalog audit: 30 saved scans, one manual note, one missing record. Identified coverage, unsupported-format, and repaired-document fail-open authorization risks. | [Batch audit](external-validation-batch-audit-2026-11-13.md), [PDF investigation](external-pdf-coverage-findings-2026-11-13.md), issues [#14](https://github.com/almuthanna1/filesmagic-security-engine/issues/14), [#18](https://github.com/almuthanna1/filesmagic-security-engine/issues/18) |
| November 14 | PDF integrity and coverage remediation validated in hosted research Lab | PR #21 added bounded page-content stream decoding, explicit coverage issues and fail-closed verdicts. The research Render engine and staging Lab ran commit 840a300c; both pinned qpdf rescans matched expected verdict behavior under reported strict isolation. | [Remediation report](pdf-coverage-remediation-2026-11-13.md), [hosted case evidence](evidence/pdf-coverage-remediation-2026-11-13/staging-840a300c-2026-11-14.json), [PR #21](https://github.com/almuthanna1/filesmagic-security-engine/pull/21) |

**Timeline qualification:** Commit dates are authoritative for code events; personal discussion dates come from meeting notes or earlier correspondence and should be cross-checked against the original calendar/email before a final academic submission. Several GitHub branches and historical documents describe different versions of the system; do not present an October architecture as if it were the November implementation.

---

## 3. Architecture: how the design evolved

### 3.1 First prototype: an explanatory multilayer scanner

The first version was a standalone FastAPI endpoint with a scanner contract, typed findings and a deterministic decision policy. It combined:
1. **YARA-X:** raw-byte signatures and curated rules. Useful for recognized patterns but blind to structures that are compressed or encoded differently.
2. **Office structural analysis:** Python ZIP/XML tooling, oletools and olefile for VBA indicators, OOXML relationships, macros, embedded objects, external templates and metadata.
3. **PDF structural analysis:** pypdf object traversal for scripts, launch actions, forms, attachments, URI targets and other risky structures.

ClamAV was part of the early plan but was intentionally removed from the low-cost deployed engine because its signature database consumed substantially more memory than the chosen Render budget allowed. It remained a possible independent laboratory reference, **not an implemented production detection layer**. The lesson was to design for real deployment constraints rather than treating a wish list as an architecture.

### 3.2 Security-first integration remains a design, not a shipped feature

The intended eventual workflow is: upload to Security Engine; validate type and size; hold the file outside conversion; inspect in a constrained worker; report a verdict and coverage; only then invoke the separate FilesMagic Conversion Engine if **every** mandatory condition passes. The original discussion also described a “quarantine buffer.” That buffer is a proposed architectural responsibility, not proof that a dedicated quarantine storage system has already been implemented.

The explicit [security-first architecture](security-first-architecture.md) rejects the earlier idea of inserting a hook inside existing conversion routes. The research Security Engine should orchestrate a separate conversion service; the existing converter remains unchanged. **As of November 13 there is no verified end-to-end production integration or conversion authorization test.**

### 3.3 Verdicts and their limitations

The implemented decision rules are:
- HIGH or CRITICAL finding: **MALICIOUS**.
- LOW or MEDIUM finding: **SUSPICIOUS**.
- No scanner ran, or scanner failure with no higher-priority threat finding: **UNABLE_TO_SCAN**.
- Otherwise: **SAFE**.

Informational findings do not escalate a verdict. This is useful for contextual explanations, but later testing exposed a significant semantic gap: “all applicable scanners returned” may be true even when no scanner recognized the file format, a parser repaired malformed data, or a scanner explicitly did not inspect certain content. **SAFE must not be treated as permission to convert** until support and coverage are separately proven.

### 3.4 Present research system and original contributions

The unified research engine consists of four reference scanners (YARA-X, PDF, Office, early custom structural) plus five new analysis modules and evidence correlation:

| Module | Question it answers | Original contribution and limitation |
|---|---|---|
| Refined YARA-X engine | Do raw-byte indicators imply an automatic trigger? | Narrower rule interpretation; still a byte-level heuristic, not behavior execution |
| PDF action chains | Which action belongs to which trigger, and does it actually deliver an attachment/script? | Bounded graph traversal of document actions and contextual risk |
| VBA call chains | Can an automatic Office entry point reach a dangerous capability? | Static call graph with linked/undetermined/no-path distinction; dynamic calls remain uncertain |
| OOXML activation graph | Does a relationship activate on open, on user action, as data, or not at all? | Contextual graph for Word/Excel/PowerPoint relationships |
| Word field codes (C7) | Do DDEAUTO, DDE, INCLUDETEXT and INCLUDEPICTURE fields request external work? | Reconstruction across runs, nested fields and tracked deletions; static and additive only |
| Evidence correlation | Are two scanners reporting the same cause? Can a false positive safely be reduced? | Evidence-bound supersession and transparent justification; never blindly remove a strong indicator |

The original custom structural work also includes C1 unnecessary hexadecimal PDF name escapes and C4–C6 OOXML package/relationship consistency checks. Third-party parsing libraries are clearly attributed in the [approved plan](custom-engine-approved-plan-2026-11-06.md) and [research log](custom-engine-research-log.md). **We wrote detectors, contextual models and tests; we did not write YARA-X, oletools or pypdf from scratch.**

---

## 4. The security engineering phase: failures that changed the design

### 4.1 Critical audit findings in the early prototype

The October 23–26 audit identified real weaknesses in the original API:

| Early problem | Why it mattered | Engineering response | Lesson |
|---|---|---|---|
| Public unauthenticated scan endpoint | Any client could submit untrusted work; CORS is not authentication. | Short-lived Ed25519 tokens bound to hash/size, one-use validation, authorization before body reads. | The trust boundary starts before parsing, not after a suspicious verdict. |
| Multipart parsing before size check | Unbounded multipart spooling could write uploaded bytes to disk before enforcing the declared limit. | Raw streaming upload with a bounded 10 MB read. | A size check is useless if a framework already parsed the entire body. |
| Parsing in API process | A document bug could hang or crash the service. | Fresh isolated child worker, timeouts, process-group termination and resource limits. | Untrusted parsers should not share the API execution context. |
| No concurrency control | Parallel 10 MB scans could exhaust a small instance. | Explicit maximum concurrent scans and rejection when busy. | Availability is part of security. |
| Overly verbose error logging | Filenames, parser errors or tracebacks may include user content. | Request IDs and sanitized failure classifications; metadata only. | Observability must not leak uploaded document content. |
| Vulnerable frontend dependencies | Research interfaces also have an attack surface. | Next.js security updates and CI audit checks. | A scanner Lab can be compromised through its UI, not just its parser. |

Source: [malware research readiness audit](malware-research-readiness.md), which distinguishes confirmed code defects from unverified environmental risks. Historical login steps in that document were later superseded by a passwordless Lab on October 28; file-bound scan tokens remain required.

### 4.2 The Render tunl0 assumption was wrong

The first strict-isolation policy assumed the worker could only have the loopback network interface. Hosted Render Linux exposed an inert, down, kernel-created IP-in-IP fallback interface named **tunl0**. A simplistic “loopback only” test refused otherwise isolated scans.

The project did **not** turn off isolation to make the test pass. It inspected interface flags, addresses and routing, established the device was inert with no usable outbound path, and allowed only that specific measured exception. The final report correctly shows **net_loopback_only=false**, **net_fallback_tunnel_inert=true**, and **network_verified=true**. CI later reproduced the condition on a real Linux runner.

**Lesson:** Security controls must be strict about meaningful properties, not merely machine-specific appearance. A permissive blanket exemption would be dangerous; a narrow, independently tested exception is defensible.

### 4.3 The offline VM exposed AppArmor and environment assumptions

An offline Ubuntu 24.04.5 VirtualBox research VM was prepared with adapters disabled, no usable routes, no shared folders, and controlled clipboard/USB transport. A dedicated Python 3.11.18 interpreter was installed under root ownership. Initial strict preflight failed when Ubuntu AppArmor refused the capability drop. Rather than disable the safety check, the student measured the denial and built an enforcing interpreter-specific profile granting only the minimum capabilities needed for namespace setup. Strict preflight was rerun.

Earlier VM tests recorded **61 passes and four environment-assumption failures**. Later Phase 6 testing uncovered another class of problem: tests that made incorrect assumptions about symlink targets, unavailable host network conditions, inaccessible system paths, and zombie-process observation. The test framework was revised to skip only **measured** inapplicable conditions and to retain hard failure for actual security bugs.

The research VM's isolation settings also **drifted** during sample-transfer setup on November 3. They were rechecked and corrected before continuing. The lesson was operational: documented controls do not stay true automatically; every scan needs a preflight and an auditable isolation record. During later work, bidirectional clipboard convenience was considered for benign result transfer, so any future hazardous-sample evaluation must reverify the physical VM isolation boundary rather than inheriting an old snapshot's assumptions.

**Sources:** [C9.2 VM validation](offline-vm-validation-c9-2.md), [Phase 6 and final runs](offline-vm-validation-phase6.md), [EICAR/Didier VM drift record](eicar-didier-evaluation.md).

### 4.4 What the October 26 hosted acceptance proved

The staging Lab/engine passed **19/19** planned acceptance checks, including token replay and mismatch rejection, malformed-file handling, timeout and recovery, 10 MB limit, sanitized logs and exports, and the **16/16 inert fixture verdicts**. A separate independent outbound-network test on Render itself was not performed, although Linux CI exercised that property. The source document marks it BLOCKED rather than pretending it passed.

This was evidence of engineering controls under a named setup, **not** proof of containment against every native parser exploit, safe processing of real malware on Render, or the correctness of arbitrary real-world verdicts.

---

## 5. From synthetic indicators to comparative experiments

### 5.1 Why we began with inert fixtures

Early experiments used deliberately constructed document structures rather than executable malicious samples. A synthetic PDF might contain an inert /Launch marker; a Word document might contain an external template relationship pointing to example.invalid; a DOCM might contain a placeholder VBA storage part without executable macros. These fixtures have known construction details and can test whether a rule fires without importing live malicious code.

Their labels are **SECURITY_TEST** or documented benign controls, not samples of known malware. A constructed file returning MALICIOUS demonstrates that the *engine policy* reacts to that indicator; it does not establish accuracy on actual attacks.

### 5.2 C10: Word external-template experiment (October 27)

An inert DOCX with an external attachedTemplate relationship was scanned in the strictly isolated VM. The raw-byte YARA-X rule set did not recognize the compressed OOXML relationship, but Office structural analysis found it. This is a concrete reason to keep a layered scanner instead of using signatures alone. The experiment used a benign control, 5 independent runs, per-scanner findings and latency records. No external template was fetched and no payload ran.

### 5.3 C10.1: Macro-project presence (October 27)

An inert DOCM-shaped OOXML package with a VBA-storage placeholder was scanned using the same engine and rules. In this case both YARA-X and Office structural analysis identified the corresponding marker. The contrast showed where a byte signature worked and where format-aware parsing added coverage. No valid macro or auto-execution was demonstrated.

The two experiments are described separately in [C10](c10-docx-external-template-experiment.md) and [C10.1](c10-1-vba-project-presence-experiment.md). Combining them into a universal “detection rate” would be scientifically unsound.

### 5.4 The mentor-driven custom-engine research protocol

At the November 6 meeting the student presented an architecture with input validation, a proposed quarantine buffer, a format router, resource limits and isolated detection components. Dr. Haque asked for specific examples at each stage, direct understanding of the methods rather than copying code blindly, license attribution, and an empirical comparison of existing versus custom components.

The approved implementation plan defined seven initial inert cases and the rule that each claim needed source, test case, expected behavior, actual result and limitation. The journal records both accepted hypotheses and rejected performance ideas. This was an important transition from a software demo to an explainable research investigation.

### 5.5 A first false claim: automatic PDF JavaScript

The custom engine initially over-associated PDF JavaScript and embedded-file indicators with automatic execution. A click-only action and an attachment elsewhere in the same document were being treated as though they were on the same automatic chain. The November 6 corrected version scoped findings to the **same trigger-to-action chain** and refined the YARA-X claim so it did not call a user-triggered script automatic without evidence.

The controlled evaluation included an over-correction guard: a destination page's actual automatic open action still had to be classified as automatic. The outcome is a lesson in evidence semantics: the presence of A and B in one file does not prove that A activates B.

### 5.6 VBA and OOXML: classify the path, not the keyword

The VBA call-graph work reconstructed possible calls from automatic entry points to capabilities and distinguished a **demonstrated path** from an ambiguous or missing path. The OOXML activation graph examined which relationship was actually loaded, clicked or merely declared. These modules added contextual evidence, not dynamic execution or a proof of payload behavior. They were later joined by C7 Word field reconstruction for DDE and remote INCLUDE instructions.

Performance hypotheses were tested rather than advertised. Measured YARA-X compiled-rule reuse or fast_scan did not justify the proposed optimization; the unified engine generally added latency because it performed additional analysis. A research report that says “more accurate on selected indicators, somewhat slower” is better than an unsupported claim of faster malware scanning.

**Source:** [custom-engine research log](custom-engine-research-log.md) and [C7 field-code design](custom-engine-c7-word-fields.md).

---

## 6. Real-world benign testing and false-positive work

### 6.1 First 29 known-benign documents (November 8)

The first substantial benign corpus contained **29** documents produced using Word, Excel, PowerPoint, LibreOffice and Edge, with varied links, tables, charts, embedded material and PDF exports. Both the reference and early unified engines ran once per file on Render under strict isolation: **58/58 scans completed**; 25/29 files received SAFE and **4/29** were flagged SUSPICIOUS by both engines.

The four warnings were explainable:
- A locally linked Word picture was classified as an external network path.
- A linked Excel workbook was likewise mistaken for a network destination.
- A local Word custom template was treated like an automatic remote template.
- A LibreOffice hybrid PDF carried an editable OpenDocument attachment, which the engine treated as unverified embedded content.

These were **known-benign corpus warnings** and therefore false positives within that explicitly labelled set. They do not imply any broader false-positive rate.

### 6.2 Improving precision without simply ignoring alerts

Three unified-only evidence-constrained corrections recognized local data-only Office targets and verified passive OpenDocument PDF attachments. The reference scanner stayed unchanged for comparison. After the initial fixes the development corpus had **1/29** SUSPICIOUS instead of 4/29, with the local template warning retained by the documented policy.

The team then **attacked its own fixes**. The first attachment verifier used overly permissive raw XML text searches and could have approved XML with alternate namespaces, encodings, script-like elements, external resources or misleading file names. The local-target logic relied too much on declared relationship type and could approve an element used as a hyperlink instead of passive data. Those reductions were hardened with namespace-aware defused XML parsing, explicit allowed uses, bounded reads, file-signature checks, and a severity ceiling that forbids discarding higher-rated evidence.

This sequence matters more than the headline 4-to-1 change: **lower false positives only count as progress if they do not create new blind spots**.

### 6.3 Held-out government documents and unresolved warnings

Four government files were used as an independent benign set. Three IRS forms were originally reported MALICIOUS by the reference scanner and SUSPICIOUS by the unified engine. The broader approval of those files' benign labels did not make their automatic JavaScript structures disappear; the project retained the warnings rather than silence them merely to obtain a favorable metric. Later source-pinned PDF accuracy experiments and the Content Credentials study addressed narrower cases.

The accepted November 11 PDF accuracy work removed a specific false signal: the raw YARA pattern /EmbeddedFile matched the *name* /EmbeddedFiles even when the name tree was empty. The fix required full structural evidence, without weakening genuine attachment warnings. A separate bounded C2PA Content Credentials study was pre-registered; the presence of that work does not mean all C2PA documents are now known safe.

**Sources:** [29-file benign corpus, fixes, security review and staging reruns](evidence/benign-corpus/README.md); [PDF accuracy preregistration](pdf-accuracy-preregistration.md); [PDF accuracy evidence](evidence/pdf-accuracy-c24c52c/summary.md); [C2PA study plan](c2pa-accuracy-preregistration.md).

---

## 7. November 9 release freeze: what was actually proven

The frozen code and evidence were recorded at **eda2a08** and tag **custom-engine-freeze-2026-11-09**, before the later external validation changes. The final offline Ubuntu experiment used an enforcing AppArmor-confined interpreter, verified isolation preflights and a read-only transfer medium with hashes checked in the guest.

| Measurement | Recorded result |
|---|---|
| Inputs | 57: 16 inert synthetic, 33 known-benign (29 development + 4 held-out), 2 truncated, 6 C7 field cases |
| Configurations | Reference engine and custom unified engine |
| Results | **114/114 expected**; 102 earlier-case results identical to Windows evidence; 12/12 C7 results as expected |
| Contribution assertions | **11/11 passed** |
| Strict isolation | All 114 scan records reported no missing required controls |
| VM tests | **993 passed, 0 failed, 11 explicitly measured environment skips**, out of 1,004 |
| Linux CI at freeze | **1,004 passed, 0 skipped**, plus 31 tunl0 scenario tests; Docker and frontend checks passed |
| Determinism | Same results on repeated trials at that code and data revision |

Two earlier attempted final VM runs were **preserved rather than erased**. Their contribution and scan results succeeded, but a process-termination test failed because AppArmor hid another process's zombie /proc entry and the test interpreted that observation incorrectly. The revised test treated inaccessible process state conservatively, without weakening the requirement to terminate the process group within five seconds. The third run passed.

**Performance:** On this one VM, median per-file wall times for synthetic cases were 409.5 ms reference versus 435.7 ms unified; for the benign corpus, 279.1 versus 316.4 ms; for C7, 294.6 versus 341.3 ms. These are not cloud or production benchmarks. The five added engine scanners consumed only a small fraction of the wall time, but the engine was **not faster** in the matched measurements.

**Freeze conclusion:** “Ready as a standalone research engine under the measured conditions.” **Not** “detects real malware with known accuracy” or “ready to control production conversion.” The frozen data must not be overwritten by November 13's extra tests.

Primary evidence: [readiness decision](engine-readiness-report.md) and [final VM run 3](evidence/final-eda2a08-run3/README.md).

---

## 8. Why the Research Lab itself changed

The first Security Lab was a separate browser-based scanner and a synthetic test download page. It acquired a password-gated evaluation view, then switched to passwordless staging access in October while retaining short-lived, signed, file-bound upload tokens. The application later supported explicit reference-vs-unified comparisons, scanner timings, request IDs, isolation evidence and local-browser result exports.

In November, the Lab was unified under one Vercel staging site. The public UI was then limited to the **custom unified engine** so demonstrations could not confuse it with the older reference configuration. A pinned collection of 10 independent research links was followed by **32 supplementary external files** from Apache POI, veraPDF, qpdf, oletools and EICAR. Repeated manual copy/paste became an evaluation workflow problem. The student requested a single-page drag-and-drop scanner, a Run Scan action, and a **Copy Full Result** function that includes actual engine evidence rather than just a manually selected verdict. PRs #10–#13 implemented that evolution.

During stress testing, the researcher also needed to submit particular **encrypted and malformed qpdf fixtures to the existing Render staging engine** to reproduce what a real converter might receive. The frontend was changed to permit **only their pinned SHA-256 bytes**, not arbitrary renamed files. The harmless oletools DOCM control and the two inert EICAR controls were later admitted under exact reference hashes. Those changes are catalog-scoped workflow choices, not an authorization to upload real malware or a substitute for backend validation.

**Important record limitation:** The “Copy recorded results” action exports **browser-local records for the 32-file catalog**, not everything ever scanned in the VM, staged API, or older Labs. A manual verdict in a dropdown is not equivalent to an engine history record.

---

## 9. The November 13 external validation: a deliberately uncomfortable outcome

The curated catalog included ordinary and structurally unusual Office files, PDF/A conformance fixtures, qpdf corrupted/encrypted documents, an oletools clean DOCM, and inert EICAR test controls. All were external to the capstone's original synthetic case matrix.

As of the uploaded batch export, **31/32 cases had entries**, but only **30** contained saved full scan reports: **21 SAFE, 8 SUSPICIOUS, 1 UNABLE_TO_SCAN**. One SAFE result (validation-03) was manual-only, and the EICAR ZIP (validation-32) was absent. **29/30** history-backed scans said complete; all 30 reported no missing required isolation controls, but seven older browser records lacked individual flag details. Median whole-scan duration was **6,882.9 ms** versus a **94.8 ms** median of the per-file sums of scanner timings. These figures should not be conflated with the offline VM's wall time.

### 9.1 Eight attachment warnings, not eight proved threats

All seven veraPDF embedded-file fixtures and qpdf add-attachments-1.pdf returned SUSPICIOUS due to **ENGINE_PDF_ATTACHMENTS_UNVERIFIED** (LOW), with **ENGINE_CORRELATION** describing merged raw PDF and YARA-X observations. Attachments included TXT, CSV, XML and unspecified names. The engine's intentionally conservative verifier knew only narrow passive types, so it did not certify these contents. The eight results are **potential false positives**, not eight confirmed false positives: source contents were not independently proven malware-negative. PDF/A PASS and FAIL mean standards conformance only, not malware labels.

### 9.2 A good failure: bad-xref.pdf

The pinned malformed qpdf **bad-xref.pdf** produced **UNABLE_TO_SCAN**, complete=false, with the PDF and PDF-chain scanners returning malformed-input errors. This is evidence of one working fail-closed parsing path. It does **not** show that all malformed documents fail closed.

### 9.3 A coverage warning inside SAFE: V4-aes.pdf

The AES-encrypted **V4-aes.pdf** returned SAFE and complete=true with two INFO findings. The PDF scanner decrypted it using an empty user password, while the custom PDF syntax scanner reported **CUSTOM_PDF_COVERAGE_LIMITED**: its raw-byte analysis could not inspect every encrypted string/stream. The result does not demonstrate a missed malicious payload, but it exposes an unresolved requirement: prove that another analyzer provides equivalent threat coverage, or block authorization when that coverage is mandatory.

### 9.4 A damaged content stream inside SAFE: bad-data.pdf

The pinned **bad-data.pdf** returned SAFE with zero findings. Its PDF syntax contains an LZW-filtered page **/Contents** stream, which the structural security analyzers intentionally skip. The run does not establish whether that particular stream decodes correctly or whether the FilesMagic converter could parse it safely. This is a **coverage-contract issue**, not a demonstrated LZW exploit. A converter-relevant bounded validation layer needs to make an explicit decision on required stream data.

### 9.5 An unsupported file classified SAFE: bad-direct-root.pdf

The malformed **bad-direct-root.pdf** began with **UPDF-1** instead of the PDF magic signature. Render correctly reported **detected_format=unknown**, but the two general YARA-X scanners completed with no match and the service returned **SAFE**, complete=true. Seven format-specific components were not applicable. If the future conversion gate blindly equated SAFE and complete with permission to convert, that could be a **fail-open authorization flaw**.

The remedy is not to pretend the malformed file is malware. It is to separate **supported format**, **scanner execution**, **required coverage** and **conversion eligibility**. An unsupported file should receive explicit rejection or UNABLE_TO_SCAN for conversion purposes regardless of generic YARA-X results.

### 9.6 Parser repair and partial coverage inside SAFE: append-xref-loop.pdf

The pinned **append-xref-loop.pdf** returned SAFE and complete=true despite **44 parser repair warnings** and **ENGINE_PDF_ATTACHMENTS_INCOMPLETE** (INFO). This case makes the distinction unavoidable: parser recovery and clean scanner return do not prove every necessary object was checked. Production authorization must treat unresolved partial coverage as non-allowing.

### 9.7 EICAR does not measure real-malware detection

The standard 68-byte **eicar.com.txt** reference control returned SAFE and no signature matches. Under the tested rules, EICAR was not recognized. That is a clear statement about a known inert signature fixture; it is **not** proof of a false-negative rate against real malware. The EICAR ZIP result was absent from the uploaded export at cutoff, and therefore cannot be assigned a verdict.

### 9.8 External-batch decision

The additional evaluation was **valuable precisely because it revealed weaknesses not visible in the controlled freeze**. The research prototype has meaningful scanner and isolation evidence, but is **not ready to authorize conversion based on the present SAFE flag**.

Full counts, hashes, request IDs and the 32-case matrix: [batch audit](external-validation-batch-audit-2026-11-13.md). PDF investigation: [coverage analysis](external-pdf-coverage-findings-2026-11-13.md). Open remediation: [issue #14](https://github.com/almuthanna1/filesmagic-security-engine/issues/14) and [issue #18](https://github.com/almuthanna1/filesmagic-security-engine/issues/18).

### 9.9 Post-freeze correction and hosted regression (November 14)

A separate correction, [PR #21](https://github.com/almuthanna1/filesmagic-security-engine/pull/21), added unified-only `pdf-integrity`, machine-readable coverage issues and a verdict policy that refuses otherwise SAFE results when required coverage is missing. It also stopped treating encryption *alone* as proof of a missing custom-C1 object stream. The PR was merged into the research branch as `840a300c1edf4682cbd4ba7ecc7f183ba281983e`, then deployed **only** to the research Render engine and Vercel Security Lab.

The student manually re-uploaded the same two SHA-256-matched qpdf fixtures, both scanned by six applicable components with zero failures and no missing required isolation controls:

- **`V4-aes.pdf`**, request `91d02883c3d8406f` at `2026-11-14T03:21:09.705Z`: SAFE, `complete=true`, 7,289.8 ms. The earlier `CUSTOM_PDF_COVERAGE_LIMITED` warning is absent; `PDF_ENCRYPTED_PERMISSIONS_ONLY` remains INFO.
- **`bad-data.pdf`**, request `b4e41e363e8b4afe` at `2026-11-14T03:21:49.299Z`: UNABLE_TO_SCAN, `complete=true`, 6,044.7 ms. The `pdf-integrity` finding `ENGINE_PDF_COVERAGE_INCOMPLETE` cites `PDF_CONTENT_LZW_DECODE_FAILED`.

The saved-history export lists the verdicts, scanner statuses, findings and worker-reported isolation flags but **does not print the raw `coverage_complete` / `coverage_issues` fields**. A separate Windows API-worker replay recorded those fields explicitly. Distinguish the two sources when reporting coverage. Source hashes, full scanner timings and evidence limitations are in [the hosted evidence record](evidence/pdf-coverage-remediation-2026-11-13/staging-840a300c-2026-11-14.json) and [the remediation analysis](pdf-coverage-remediation-2026-11-13.md). The November 9 frozen evaluation is unchanged. These two targeted cases do not resolve unrelated unknown-format, parser-repair, attachment-policy or converter-integration concerns.

---

## 10. Research failures and what we learned

| Failure or friction | Evidence | What we learned | Status as of Nov 13 |
|---|---|---|---|
| Heavy AV engine unsuitable for deployment budget | Early ClamAV evaluation | Choose capability-aware layers and report trade-offs honestly. | Direction changed to YARA-X plus structural analysis |
| Public scan endpoint and upload spooling | Original implementation security audit | Validate trust and bound input **before** parsing. | Fixed in hardened research API |
| Parsing in the API process | Original audit | Isolate work from the HTTP service; timeouts must kill process groups. | Per-scan worker implemented and tested |
| Loopback-only test rejected inert tunl0 | Render staging and Linux CI | Prove absence of network routes; avoid blanket exceptions. | Narrow verified alternative implemented |
| AppArmor denied capability drop | Ubuntu VM C9.2 | Fail closed and fix the profile rather than disable isolation. | Repaired and confirmed |
| VM device/clipboard settings drifted | November 3 VM review | Reverify host and guest isolation before hazardous work. | Corrected for recorded runs; re-check before future samples |
| Process/zombie tests misread /proc permissions | Final VM runs 1/2 | Tests also have threat models and environment assumptions. | Tests corrected, third run passed |
| Automatic-action evidence overclaimed | PDF chain cases 5a/5b | Presence is not reachability; report trigger-to-payload paths. | Corrected with regressions |
| Local files misclassified as remote exfiltration | Benign DOCX/XLSX | Verify actual activation and target semantics, not labels alone. | Qualified, evidence-bound corrections |
| Initial FP correction could hide active XML/links | Security review of the three superseding rules | Precision improvements must be adversarially reviewed. | Hardening rules and negative tests added |
| YARA-X fast-scan speed hypothesis did not pay off | Custom research profiling | Record rejected optimizations, not just successes. | Rejected by measurement |
| Browser result tracking originally copied dropdown only | November 13 user evaluation | Research tooling must preserve actual SHA, rule, version and isolation evidence. | Full report and inline scan implemented |
| Unverified attachments warned on routine data fixtures | Eight external cases | Conservative policy has a compatibility cost; verify bytes, not extensions. | Open coverage/false-positive investigation |
| Unknown or partly inspected PDF returned SAFE | qpdf external cases 24–28 | Completion is not complete threat coverage; conversion needs its own allow decision. | **Open production blockers** |
| EICAR inert control returned SAFE | November 13 EICAR TXT | A curated rule set is not antivirus coverage; benchmark scope must be explicit. | Signature support decision open |

---

## 11. Research methodology and evidence standards

### 11.1 Four evidence categories

1. **Unit and regression tests:** prove particular code paths and invariants; high repeatability but constructed inputs.
2. **Inert indicator experiments:** demonstrate detection and context on synthetic features; not genuine malware accuracy.
3. **Known-benign and sourced regression corpora:** show compatibility, false warnings on labelled benign documents, and error handling; not a representative threat benchmark.
4. **Offline isolated VM and deployed staging:** establish how a particular release behaves under measured containment and operational constraints.

Each claim should identify: **date, environment, commit, ruleset hash, file SHA-256, sample provenance, ground-truth status, expected vs observed outcome, scanner completeness, isolation, and limitations**. Keep multiple measurements on the same physical file separate from independent sample counts.

### 11.2 What to say and what not to say

Permissible: “A known synthetic PDF action chain was classified MALICIOUS by policy”; “33 known-benign inputs were used in the frozen VM study”; “an externally sourced qpdf fixture returned SAFE with an unresolved coverage INFO”; “Linux CI isolation tests passed in their environment.”

Not supported: “This catches 100% of malware”; “all SAFE documents are harmless”; “Render is a fully isolated malware sandbox”; “we scanned live malicious Office documents in production”; “frozen VM and November 13 browser results are one combined accuracy benchmark”; “the conversion service is now protected by the new scanner.”

### 11.3 Ethics and operational boundaries

The live research Lab is **not a substitute for a dedicated malware laboratory**. Genuine malicious samples require institutional review, provider authorization, a specific handling plan and the correct offline containment. The host, browser, clipboard and transport channels are also part of the threat model. Neither synthetic inert tests nor EICAR are genuine malware. No untrusted sample should be opened in Office, Acrobat or a normal preview application merely to inspect it.

---

## 12. What needs to happen before production integration

**November 14 status qualification:** The research unified engine now implements explicit coverage fields and bounded PDF content checks for selected cases. The gates below remain **production-authorization requirements**: format eligibility, converter-specific coverage, integration and independent external validation are not completed by the two hosted PDF rescans.

**Gate A: Explicit coverage contract (high priority).** A versioned result must distinguish (i) execution of every applicable scanner, (ii) supported file type, (iii) required object and stream inspection, (iv) isolation, and (v) authorization to pass the bytes to a converter. INFO-level skipped/unknown analysis must not silently allow conversion.

**Gate B: Fail-closed policy and regression fixtures.** Unsupported or unknown types, failed scans, incomplete attachment traversal, unresolved encryption, important parser repairs and required stream decoding errors must block conversion authorization. Preserve a higher-priority MALICIOUS finding if one exists; do not mislabel a corrupt document as malicious simply for being corrupt. Add positive and negative tests for all new rules.

**Gate C: Narrowly improve confirmed coverage gaps.** For empty-password encrypted PDFs, inspect decrypted objects to an equivalent, documented standard or retain non-allow coverage evidence. For converter-relevant compressed streams, use bounded inspection with per-stream and cumulative limits. Validate qpdf fixtures independently before claiming a specific malformed decode. For passive TXT/CSV/XML attachments, inspect bytes and activation context instead of blanket extension allowlisting.

**Gate D: Measure again without contaminating the baseline.** Use a new commit, fixed manifests, the same pinned regression corpus and additional benign controls. Report before/after verdicts, errors, extra work and latency. Keep the November 9 freeze intact.

**Gate E: Design and prove the real orchestration.** The Security Engine, rather than an unverified pre-conversion hook, should be the entry point that calls the independently hosted FilesMagic Conversion Engine only after authorization. Test actual denial paths, timeouts, replay, concurrency, unsupported conversion formats, resource exhaustion and failure recovery. The conversion engine should not be able to bypass the gate on an alternate upload route. The current live FilesMagic Conversion Engine has not been changed by the capstone.

**Gate F: External validity and approvals.** An independently labelled, legally and operationally approved threat corpus is still needed to estimate detection metrics. Until then, report selected indicator coverage and benign compatibility, **not general malware accuracy**.

---

## 13. Project outputs and academic presentation

The project has already produced more than a single scanner:
- A reproducible FastAPI service and browser-based Security Lab.
- A baseline and custom unified research architecture, with original detectors and code attribution.
- A documented isolation and access-control design tested in Linux CI and in a disconnected VM.
- A synthetic fixture library, case-matrix harness, real-world benign corpus, preregistered PDF studies and recorded external regression results.
- A mentor-reviewed architecture proposal, capstone evidence package, poster draft, figures, and presentation/demo runbooks.
- A dated research log that records mistakes, changes of hypothesis, test failures, and limitations.

The November 6 mentor meeting established a **November 18 poster submission deadline** and **December 3, 4:00–5:15 p.m. presentation** at the Barsima Alumni Center, with setup beginning at 3:30 p.m. The mentor recommended visualizing architecture, outcomes and limitations and reviewing a draft before submission. This historical schedule is not evidence that a future presentation has already occurred.

Existing supporting material: [poster draft](poster/poster-draft.md), [poster figures](poster/figures/comparison.md), [presentation outline](capstone-presentation-outline.md) and [demo runbook](capstone-demo-runbook.md). Some older demonstration instructions describe the former admin login and should be revised before use.

---

## 14. Open questions and missing historical evidence

1. **Early conception:** attach the original September advisor email or proposal, and clarify whether any significant preparatory work preceded October 8.
2. **Architecture diagram versions:** preserve each Figma/PowerPoint version with date and identify which boxes were aspirational (especially quarantine, production routing) versus implemented.
3. **Week-by-week time investment:** import a calendar or work log to estimate hours. Git commits are not a reliable time-tracking record.
4. **Originality audit:** list each custom algorithm, upstream dependency and license in one current table, not only in the November 6 plan.
5. **External batch closure:** validation-03 needs a full history-backed report; validation-32 requires a recorded result or explicit rejection.
6. **Independent parsing:** the exact qpdf LZW fixture was reproduced as a decoder failure using bounded pypdf and a hosted regression; repaired cross-reference cases and conversion-engine-specific behavior still need independent characterization.
7. **UI and backend version split:** capture exact Vercel deployment, Render deploy and engine commit at each evaluation. A UI commit is not proof that the backend changed.
8. **Actual future product gate:** document a threat model for the conversion service, upload paths, authorization and rollback before writing integration code.
9. **Academic deliverables:** attach advisor feedback, final poster version, rubric, final presentation and any project report when available.
10. **Evaluation scope:** the initial capstone emphasized original techniques, not a comprehensive security product. Decide and document what is explicitly out of scope.

---

## 15. Source register and reproducibility map

### Primary process records
- [Repository commit history](https://github.com/almuthanna1/filesmagic-security-engine/commits/feature/custom-unified-engine-nov18/)
- [Initial capstone evidence package, October 26](capstone-evidence-package.md)
- [Approved November 6 research plan](custom-engine-approved-plan-2026-11-06.md)
- [Custom engine research log](custom-engine-research-log.md)
- [Offline VM validation C9.2](offline-vm-validation-c9-2.md)
- [Offline VM Phase 6/final-run history](offline-vm-validation-phase6.md)
- [Final November 9 release-readiness report](engine-readiness-report.md)
- [External November 13 batch audit](external-validation-batch-audit-2026-11-13.md)
- [Post-freeze PDF coverage concerns](external-pdf-coverage-findings-2026-11-13.md)
- [November 14 PDF remediation and hosted validation](pdf-coverage-remediation-2026-11-13.md) and [hosted scan-history transcription](evidence/pdf-coverage-remediation-2026-11-13/staging-840a300c-2026-11-14.json)

### Experiments, datasets, and controlled outcomes
- [C10 Word external template](c10-docx-external-template-experiment.md) and [C10.1 inert VBA project](c10-1-vba-project-presence-experiment.md)
- [EICAR and Didier Stevens evaluation plan](eicar-didier-evaluation.md)
- [Benign corpus and false-positive audit](evidence/benign-corpus/README.md)
- [Frozen November 9 run 3 artifacts](evidence/final-eda2a08-run3/README.md)
- [PDF attachment accuracy preregistration](pdf-accuracy-preregistration.md) and [results](evidence/pdf-accuracy-c24c52c/summary.md)
- [C2PA verification preregistration](c2pa-accuracy-preregistration.md)
- [C7 Word fields](custom-engine-c7-word-fields.md)
- [Current unit and isolation checks](../tests/) and [GitHub Actions workflow](../.github/workflows/security-engine-tests.yml)

### Decision and change tracking
- [Production conversion design, proposed](security-first-architecture.md)
- [Issue #14: required coverage and conversion gate](https://github.com/almuthanna1/filesmagic-security-engine/issues/14)
- [Issue #18: unknown format must not authorize conversion](https://github.com/almuthanna1/filesmagic-security-engine/issues/18)
- [Lab changes in PRs #10–#17](https://github.com/almuthanna1/filesmagic-security-engine/pulls?q=is%3Apr+10+11+12+13+16+17)
- Student-owned November 6 mentor audio/transcript and working files are **private working sources** and are not published in this repository.

---

## 16. Maintaining this journal

Update after each substantive milestone. For each addition, record:

| Field | Required entry |
|---|---|
| Date and research question | What were we trying to learn? |
| Code and environment | Commit SHA, branch, OS, deployment/VM, engine/ruleset versions |
| Hypothesis and method | Input/corpus, label source, expected rule behavior, repetitions |
| Observation | Actual verdict, findings, failures, timing and isolation with artifact link |
| Interpretation | What the observation supports and what it does not support |
| Failure and decision | Root cause, why we changed or retained the approach |
| Next validation | Specific regression case and passing/failing acceptance condition |

**Revision log**

| Version | Date | Change |
|---|---|---|
| 0.1 | 2026-11-13 | First integrated chronological draft from Git commits, existing capstone documentation, November 6 meeting notes, frozen VM evidence and external-case audit. Unverified historical details explicitly listed in Section 14. |
| 0.2 | 2026-11-14 | Added post-freeze PDF coverage remediation and two manual hosted qpdf regression outcomes at merge commit 840a300c, with request IDs, strict-isolation observations and separate evidence limits. November 9 totals preserved. |

**Research posture:** Document the failures with the same precision as the successful milestones. The capstone's central result may ultimately be a defensible security architecture, a narrower custom detection contribution and an empirical statement of its limits. That is stronger research than a claim that a prototype is already perfect.
