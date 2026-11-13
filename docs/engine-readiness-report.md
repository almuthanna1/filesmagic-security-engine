# FilesMagic custom unified engine: readiness report

> **Post-freeze update (2026-11-13):** [External PDF coverage findings and remediation plan](external-pdf-coverage-findings-2026-11-13.md) document newly observed encrypted and damaged-data qpdf tests. They are **not included** in the November 9 frozen results or readiness decision below.
> **Supplementary batch audit (2026-11-13):** [32-case external validation audit](external-validation-batch-audit-2026-11-13.md) reviews 30 saved scans, one manual record and one missing case. Findings include an unsupported-format SAFE decision and incomplete/repaired PDF coverage concerns. They do not alter the frozen dataset.

| | |
|---|---|
| Release | tag `custom-engine-freeze-2026-11-09`, branch `feature/custom-unified-engine-nov18` |
| Validated code | commit `eda2a08`. The tagged commit changes only files under `docs/` (this report, the run-3 evidence, two status notes). |
| Date | 2026-11-09 |
| Scope | The standalone engine: research branch, Linux CI and the offline research VM. It is not integrated with the FilesMagic Conversion Engine. Production FilesMagic and `main` are unchanged. |
| Project | NIU CSCI 499 Honors Capstone. Student: Almuthanna Shihab. Supervisor: Dr. Nur Imtiazul Haque. |

## 1. Decision

**Ready as a standalone research engine, and frozen.** The final offline validation (run 3)
passed every condition set for the freeze:
- 11/11 contribution checks;
- 114/114 scan results as expected: 102 identical to the Windows evidence (verdict and every
  finding, INFO included) and 12 C7 verdicts as specified;
- strict isolation on every result, with no missing control; every result the same in every trial;
- test suite: 1004 tests, 993 passed, 0 failed, 0 errors, and exactly the 11 documented
  environment skips.

What this does **not** establish:
- detection of real malware (none was used);
- accuracy on real-world documents beyond the 33 known-benign files;
- production readiness.

The integration with the Conversion Engine is the next step (Section 8). It is not implemented.

## 2. Validation record

| Where | Commit | Result | Evidence |
|---|---|---|---|
| Offline Ubuntu 24.04 VM: no network, interpreter confined by AppArmor (`filesmagic-eval-python`, enforce), strict isolation required | `eda2a08` (run 3) | as in Section 1. Process-group termination verified in both modes (about 2 s of the 5 s deadline). | [evidence/final-eda2a08-run3/](evidence/final-eda2a08-run3/README.md): 9 files, hashed in the guest and verified on the host |
| Linux CI: GitHub Ubuntu runner, Python 3.11, non-root, `FM_REQUIRE_LINUX_TESTS=1` (no skip allowed) | `eda2a08` | 1004 passed, 0 skipped. Isolation tests rerun with the `tunl0` fallback device: 31 passed. Docker image and Security Lab jobs passed. | [run 42560141057](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/42560141057) |
| Windows 11 development laptop, Python 3.14.3 (no Linux isolation) | code and tests of `eda2a08` | 963 passed, 41 skipped (Linux-only) | not archived |
| Research staging (Render engine, Vercel Lab) | `9111e5a`, **before C7** | 36/36 security-review scans equal to the local results, strict isolation | [evidence/benign-corpus/](evidence/benign-corpus/README.md) |

Two earlier final runs are kept as found:
- [run 1 at `d80a46d`](evidence/final-d80a46d-run1/README.md);
- [run 2 at `6907929`](evidence/final-6907929-run2/README.md).

Each passed all 11 claims and every result check, but stopped on one test failure. Both failures
came from how a test *observed* process termination under the VM's AppArmor profile: a zombie's
`/proc/<pid>/stat` is owned by root, and the profile allows reading only the caller's own
entries. Neither failure was an engine or worker defect. The corrections changed test code only;
the assertion and its 5-second deadline are unchanged. Details:
[offline-vm-validation-phase6.md](offline-vm-validation-phase6.md), Section 7.

## 3. Engine composition

The unified engine = the four reference scanners (unchanged) + five engine scanners + evidence
correlation. The isolated worker runs it with `--engine=unified`. The API offers it only where
`SECURITY_ENGINE_RESEARCH_ENGINES=1` (research staging). Elsewhere `/scan` runs the reference
engine, and a request for the unified engine is refused (HTTP 403), never silently replaced.

### 3.1 Reference engine (unchanged by this work)

| Scanner | Basis | Reports |
|---|---|---|
| `yara-x` | YARA-X 1.21.0, 9 rules (`app/rules/filesmagic.yar`) | byte patterns; blind to `#xx` name escapes and compressed streams |
| `pdf` | pypdf 6.19.0 (`app/scanners/pdf.py`) | JavaScript, Launch, URI schemes, attachments, forms. "Automatic" applies to everything reachable from an automatic trigger. |
| `office` | oletools 0.60.2, olefile, msoffcrypto-tool (`app/scanners/office.py`) | VBA (an automatic entry and a strong behaviour = HIGH), OLE objects, ZIP abuse, external relationships, DDE |
| `custom` | own code from earlier phases (`app/scanners/custom/`) | C1: PDF names with unnecessary `#xx` escapes, also in object streams. C4-C6: OOXML declaration consistency, relationship graph, ZIP metadata. |

Verdict (`app/decision`):
- any HIGH or CRITICAL finding: MALICIOUS;
- LOW or MEDIUM: SUSPICIOUS;
- no scanner ran, or one failed: UNABLE_TO_SCAN. A finding outranks a failure.
- otherwise SAFE.

### 3.2 Engine additions (this branch)

| Component (scanner) | Code | Decides | Rules (severity) | Tests in run 3 |
|---|---|---|---|---|
| Refined PDF signature (`yara-x-engine`) | `app/engine/rules/pdf.yar` | JavaScript together with a trigger that the bytes do not prove to be user-only | `ENGINE_PDF_JavaScript_With_Automatic_Trigger` (MEDIUM) | `test_engine_signatures` 39 |
| PDF action chains (`pdf-chains`) | `app/engine/pdf_chains.py` | for each trigger, the actions it starts (ISO 32000-1, 12.6) and what they deliver | `ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT` HIGH, `_LAUNCH` HIGH, `_OPENS_EMBEDDED_DOCUMENT` MEDIUM, `_SCRIPT` MEDIUM; `ENGINE_PDF_USER_TRIGGERED_SCRIPT`, `ENGINE_PDF_CHAINS_REPAIRED` INFO | `test_pdf_chains` 18 |
| PDF attachment verification (inside correlation) | `app/engine/pdf_attachments.py` | whether every attachment is an OpenDocument file without code or external references, in a PDF without actions | `ENGINE_PDF_ATTACHMENTS_VERIFIED` INFO, `_UNVERIFIED` LOW, `_INCOMPLETE` INFO | part of `test_false_positive_fixes` 51 |
| VBA call graph (`vba-chains`) | `app/engine/vba_chains.py` | whether an automatic procedure's calls reach a dangerous capability | `ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY` HIGH; `ENGINE_VBA_CALL_PATH_UNDETERMINED`, `ENGINE_VBA_NO_CALL_PATH` INFO | `test_vba_chains` 55 |
| OOXML activation graph (`ooxml-links`) | `app/engine/ooxml_links.py`, `file_paths.py` | whether a relationship is used, and when (on open, on a user action, displayed, never); whether its target is a local drive path (RFC 8089) | `ENGINE_OFFICE_EXTERNAL_ON_OPEN` MEDIUM; `ENGINE_OFFICE_LOCAL_TEMPLATE` LOW; `_LINKED_PICTURE`, `_LOCAL_FILE_TARGETS`, `_EXTERNAL_ON_USER_ACTION`, `_EXTERNAL_NOT_ACTIVATED`, `_EMBEDDED_OBJECT_DISPLAYED`, `_EMBEDDED_OBJECT_NOT_DISPLAYED`, `_ACTIVATION_UNDETERMINED` INFO | `test_ooxml_links` 53, `test_file_paths` 42 |
| Word field codes, C7 (`word-fields`) | `app/engine/word_fields.py` | DDE, DDEAUTO, INCLUDETEXT and INCLUDEPICTURE in every part Word loads; live text only, tracked deletions recorded | `ENGINE_WORD_DDEAUTO_PROGRAM` HIGH; `_DDE_PROGRAM`, `_REMOTE_INCLUDE` MEDIUM; `_DDE_APPLICATION` LOW; `_WEB_PICTURE`, `_LOCAL_INCLUDE`, `_DELETED_INSTRUCTION`, `_FIELDS_UNDETERMINED` INFO | `test_word_fields` 69 |
| Evidence correlation | `app/engine/correlate.py` | reconciles reference and engine findings by rule ID, failing closed | `ENGINE_CORRELATION` INFO: every decision recorded | `test_correlate` 13, `test_api_engines` 51 |

Design rules shared by every component:
- Analysis is static. Nothing is executed, rendered, updated or fetched, and all of it runs
  inside the isolated worker.
- A reference finding is replaced only under its rule's precondition:
  - every scanner involved completed;
  - for PDF, pypdf repaired nothing;
  - only three rules may lower a finding (local file targets, local template, verified
    attachments), and each only up to the severity it was validated on. A higher-rated finding
    stands.
- A YARA-X match is never removed, and neither is `OFFICE_MACRO_AUTOEXEC_EXECUTION`. C7 is
  purely additive.

## 4. Original work and reused components

### 4.1 Original (this repository)

1. **PDF action-chain model.** A chain is one trigger and the actions it starts: its action and
   the `/Next` sequence, nothing else.
   - The catalog is walked depth-first with a `(object, generation)` visited set; each chain is
     followed breadth-first over `/Next`, keeping references unresolved.
   - Payloads: `Launch` of an embedded file, `exportDataObject`-family calls, `GoToE`.
   - Explicit bounds on objects, depth, actions and script text.
2. **Correlation policy.** Fixed severities per chain kind (nothing is added up), supersession
   only under complete evidence, and every decision recorded.
3. **Refining a signature by subtraction.** The engine's YARA-X rule removes only the
   occurrences its own bytes disprove. On 11 PDF cases, false "automatic" claims went from 3 to 0
   and no true claim was lost.
4. **VBA call graph.**
   - A lexer and a procedure graph, with call resolution for `Run`, `OnTime`, `OnKey`,
     `CallByName` and `AddressOf`.
   - A breadth-first search from the automatic entries, with three outcomes: linked,
     undetermined or no path.
   - The search never lowers the reference verdict. VBA stomping cannot be checked on in-memory
     files.
5. **OOXML activation graph.** A breadth-first search over the loaded parts, recording each
   part's chain, followed by element-level classification of how each relationship is used
   (ECMA-376 / ISO/IEC 29500).
6. **Local-target and attachment verification.**
   - Drive paths: RFC 8089 classification, ASCII-only.
   - Office targets: every referencing element must load the target as data.
   - PDF attachments: each is parsed as an OpenDocument package (namespace-aware, any
     encoding) and checked for code, embedded objects and external references, under bounded
     decoding.
7. **Word field reconstruction (C7).**
   - Instructions are rebuilt across runs, from `fldChar` begin/separate/end and `fldSimple`,
     with nested fields kept as placeholders.
   - Tokenising follows 17.16.1.
   - Classification is by field type and first argument, on the live text only.
8. **Evaluation and verification harness.**
   - Inert case matrix: `evaluation/cases.py`.
   - `evaluation.offline_validation` refuses to scan unless all of these hold: confinement,
     offline host, a clean expected commit, no dependency drift, manifest match, and a complete
     preflight.
   - Measured, never assumed, environment skips: `tests/environment.py`.
   - Conservative process observation: `tests/processes.py`.

### 4.2 Reused, as installed libraries (no upstream source copied)

| Component | Version | License | Used for |
|---|---|---|---|
| YARA-X (VirusTotal) | 1.21.0 | BSD-3-Clause | compiling and running the rules |
| pypdf | 6.19.0 | BSD-3-Clause | PDF parsing with decompression limits; `raw_get` for unresolved references |
| oletools (P. Lagadec) | 0.60.2 | BSD-2-Clause | VBA extraction and keyword analysis (`VBA_Parser`, `VBA_Scanner`, autoexec keywords) |
| pcodedmp | 1.2.6 | **GPL-3.0** | not imported here; oletools loads it for P-code. Must be disclosed. GPL obligations apply if the Docker image is distributed. |
| olefile | 0.47 | BSD-2-Clause | OLE2 containers |
| defusedxml | 0.7.1 | PSF-2.0 | XML parsing with DTDs and entities refused |
| msoffcrypto-tool | 6.0.0 | MIT | encryption detection |

Specifications relied on: ISO 32000-1:2008 (PDF actions and triggers), ECMA-376 / ISO/IEC 29500
(OPC relationships, WordprocessingML fields 17.16), RFC 8089 (file URIs). No Office application or
PDF reader was run; behaviour beyond the specifications is not modelled. Full attribution:
[custom-engine-research-log.md](custom-engine-research-log.md), Section 3.

## 5. Evidence for each contribution (run 3 unless stated)

| # | Contribution | Shown by | Further evidence |
|---|---|---|---|
| 1 | Chain correlation removes an unjustified MALICIOUS and keeps a justified one | 5a: reference MALICIOUS, unified SUSPICIOUS. 5b: unified MALICIOUS with `ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT`. On the 3 held-out IRS forms (benign, not used to design any fix): reference MALICIOUS, unified SUSPICIOUS. | research log Sections 7-8; `benign-corpus` README |
| 2 | The refined signature is more precise without becoming weaker | fires on every automatic script case (2c, 5a, 5b); silent on the user-triggered ones (2, 2b), which the reference rule flags | research log Section 12 |
| 3 | Static macro analysis qualifies but never clears | case 7: `ENGINE_VBA_CALL_PATH_UNDETERMINED`, reference macro findings kept; 55 tests | research log Sections 13, 15 |
| 4 | Relationships are judged by use, not presence | 6c: template used on open (`ENGINE_OFFICE_EXTERNAL_ON_OPEN`); 6g: file-share target keeps `OFFICE_EXTERNAL_NETWORK_PATH`; 6e/6f: object displayed / not displayed | research log Sections 16, 19 |
| 5 | Benign false positives corrected only with complete evidence | docx-04, xlsx-04 (local targets) and pdf-07 (verified attachment): reference SUSPICIOUS, unified SAFE. docx-05 (local template): lowered to LOW, still SUSPICIOUS. | `benign-corpus` README: development set 4 to 1, security review of the three rules |
| 6 | C7 finds field-code techniques the reference misses, without false alarms on ordinary fields | c7a nested DDEAUTO: unified MALICIOUS. c7c remote INCLUDETEXT and c7d file-share INCLUDEPICTURE: unified SUSPICIOUS. The reference is SAFE on all three. c7b keeps the reference HIGH. c7e (DDEAUTO only in a tracked deletion) and c7f (ordinary fields): SAFE in both engines. | [custom-engine-c7-word-fields.md](custom-engine-c7-word-fields.md); 69 tests |
| 7 | Fail closed | truncated PDF and DOCX: UNABLE_TO_SCAN in both engines, with the parsing scanners listed as failed | run 3 results |
| 8 | Isolation is verified, not assumed | every one of the 114 results under strict isolation, with nothing missing; guest checks all PASS; profile hash unchanged | run 3 `run_status.json`, `guest-checks.txt` |

Verdicts on the 33 known-benign files (29 development, 4 held out):

| Engine | SAFE | SUSPICIOUS | MALICIOUS |
|---|---|---|---|
| reference | 26 | 4 | 3 |
| unified | 29 | 4 | 0 |

The 4 unified SUSPICIOUS files are docx-05 (local template, LOW by design) and the 3 IRS forms
(automatic JavaScript). The 16 synthetic cases are benign by construction and carry constructed
indicators. Their verdicts measure how indicators are handled, not maliciousness.

## 6. Performance (run 3; one VM on one laptop, not a benchmark)

Median over files of each file's median wall time:

| Set | Reference | Unified |
|---|---|---|
| synthetic | 409.5 ms | 435.7 ms |
| corpus | 279.1 ms | 316.4 ms |
| C7 | 294.6 ms | 341.3 ms |

Starting the isolated worker dominates the wall time. The five engine scanners together take a
median of 2.1 ms (synthetic), 5.2 ms (corpus; at most 53.3 ms, on the IRS forms) and 1.6 ms (C7)
per file. The rest of the difference is worker overhead that this run does not break down.

## 7. Remaining limitations

- **Evidence scope.**
  - Inert synthetic cases and 33 known-benign files only. No real malware was analysed, so no
    detection rate is claimed.
  - The corpus comes from one machine and two producer families, plus 4 government documents.
- **Static analysis.**
  - No Office application or PDF reader is run.
  - Computed JavaScript is not followed, XFA scripts are not modelled, and `GoToE` targets are
    named but not analysed.
  - VBA P-code (stomping) cannot be checked in memory.
  - Nested Word fields are not computed; they are treated as the worse case.
- **Not covered.**
  - Word fields: RTF, binary `.doc`, Excel DDE and PowerPoint fields; `LINK`, `HYPERLINK`,
    `MERGEFIELD` and `DATABASE` fields; `w:altChunk` content; the `w:updateFields` setting.
  - Other OOXML features: Excel `externalLink` parts, custom XML data bindings, recursive
    embedded packages.
- **Shared parser.** The PDF scanner and the chain analysis both use pypdf, so a pypdf/reader
  differential affects both. This is why YARA-X matches are never removed and a repaired
  structure disables supersession.
- **Verdict meaning.**
  - Legitimate active documents stay SUSPICIOUS: forms with automatic JavaScript, local
    templates.
  - SAFE means no known indicator was found, not that the file is harmless.
- **Isolation** (full list: [capstone-evidence-package.md](capstone-evidence-package.md),
  Section 16).
  - The worker is not a sandbox: it shares the API's user, container, filesystem view and kernel.
  - Kernel and native-parser exploits are out of scope.
  - API egress is unrestricted on Render.
  - A compromised worker could forge its report.
  - Isolation is checked once, at worker start.
  - In the VM, the profile lets the evaluation write to its results folder and `/tmp`.
- **Staging lags the release.** Render runs `9111e5a`, from before C7. C7 is validated locally,
  in Linux CI and in the VM, not on staging.
- **Tests the VM cannot run.** 11 tests cannot run under the VM's profile by design: 9 need
  bash, 2 need a host network. They run in Linux CI, where no skip is allowed.
- **Licensing.** The GPL-3 pcodedmp dependency (Section 4.2).

## 8. Freeze and next steps

- **Frozen.** The standalone engine at `custom-engine-freeze-2026-11-09`.
  - No further detectors or engine changes on this release.
  - A defect shown by evidence would be fixed in a new, separately validated and tagged release.
- **November 18 (capstone):** evaluation write-up, documentation and poster, from this evidence.
- **December 3 (integration target):**
  - The intended architecture is [security-first-architecture.md](security-first-architecture.md):
    the Security Engine is the entry point and calls the unchanged Conversion Engine only for a
    complete SAFE scan with every control passed.
  - Exact staging steps are proposed separately and not deployed. Production FilesMagic is not
    changed without approval.
