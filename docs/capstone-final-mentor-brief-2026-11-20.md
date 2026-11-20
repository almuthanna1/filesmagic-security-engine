# CSCI 499: Faculty Mentor Review Brief
**Prepared:** November 20, 2026  
**Student:** Almuthanna Shihab  
**Faculty mentor:** Dr. Nur Imtiazul Haque  
**Project:** FilesMagic Security Engine  
**Repository:** https://github.com/almuthanna1/filesmagic-security-engine  
**Scope:** Academic research implementation and evidence; not an antivirus certification.

## 1. Mentor's November 20 feedback and completion criterion

Dr. Haque approved the poster overall (the Honors poster was accepted for printing) but emphasized that integrating YARA-X, PDF parsers, and Office-analysis libraries is not, by itself, the core academic contribution. For a high grade, the student must demonstrate *substantive original malware-analysis logic*, understand exactly how it works, and describe the learning, experiments, and difficulties. The mentor explicitly allowed building on existing source or libraries **when the student fully understands the specific implemented analysis**. A simplistic file-size threshold would not satisfy this expectation.

**Scope statement:** The original contribution is the authored contextual static-analysis algorithms and their evidence policies. Established parsers and signature engines are correctly attributed rather than presented as recreated from scratch. The project makes no claim of detecting all malware.

**Action for the student before mentor approval:** Walk Dr. Haque through one original algorithm end to end, answer implementation questions without relying on the UI or automated narration, and show tests distinguishing related from unrelated indicators. Faculty review and grading remain pending.

## 2. Originality and dependency boundary

| Component | Original implementation in this repository | Reused infrastructure or libraries | Evidence |
| --- | --- | --- | --- |
| PDF action chains | Build trigger-to-action graph; traverse /Next actions with cycle detection and bounded depth; link attachments only when referenced on the same chain; report automatic versus user-triggered behavior | pypdf parses PDF objects; existing PDF scanner supplies parsing limits | app/engine/pdf_chains.py; tests/test_pdf_chains.py |
| VBA call graph | Clean and parse VBA procedures, build demonstrated/possible call edges, BFS from auto-execution entry points, classify linked/no-path/undetermined, preserve uncertainty and evidence | oletools extracts macros and supplies keyword/entry-point knowledge; existing Office scanner supplies format and resource limits | app/engine/vba_chains.py; tests/test_vba_chains.py |
| OOXML activation graph | Associate relationship targets with their actual activation context, distinguish data-only relationships from potentially loaded-on-open content | Standard ZIP/XML parsing and existing OOXML package helpers | app/engine/ooxml_links.py; tests/test_ooxml_links.py |
| C7 Word field analysis | Reconstruct fields across runs/nesting/tracked changes; classify DDEAUTO, DDE, INCLUDETEXT and INCLUDEPICTURE with content and target context | Safe XML and ZIP parsing | app/engine/word_fields.py; tests/test_word_fields.py |
| C1/C4-C6 structural anomalies | Detect selected PDF escaped-name patterns and OOXML declaration, relationship and container inconsistencies | Python format handling; standard file specifications | app/scanners/custom/pdf.py; app/scanners/custom/ooxml.py; tests/test_custom_pdf.py; tests/test_custom_ooxml.py |
| Evidence correlation | Reconcile overlapping findings under explicit preconditions, retain higher-risk evidence on parser uncertainty and missing coverage, provide explainable classifications | YARA-X engine plus reference Office/PDF scanners | app/engine/correlate.py; tests/test_correlate.py |

**Attribution:** YARA-X (VirusTotal), pypdf, oletools/olevba and related packages are dependencies, not student-authored engines. The precise dependency/license inventory is in docs/custom-engine-research-log.md section 3; note the indirect GPL-3 pcodedmp dependency. Do not claim pypdf's PDF parser, olevba's VBA decompression, or YARA-X's pattern matcher as original.

## 3. Flagship technical contribution A: contextual PDF action-chain analysis

**Problem in the reference implementation:** A document with an automatic JavaScript action and a separate unrelated attachment could be classified at the same severity as a document whose automatic action explicitly reaches or exports that attachment.

**Original algorithm (app/engine/pdf_chains.py):**
1. Parse the file into PDF objects using pypdf under configured decompression and object limits.
2. Traverse supported document structures and identify explicit triggers such as /OpenAction and /AA; do not infer that a clicked annotation becomes automatic because a page was opened.
3. For each trigger, build *its own* action sequence by following /Next. Use visited-object sets to terminate cycles; impose hard bounds on objects, depths, script text, and actions.
4. Describe script, launch, external and embedded-file use. Match an attachment to a chain only when that same chain references it.
5. Pass the resulting structured evidence to app/engine/correlate.py, which applies contextual severity rules and retains reference evidence if a required scanner failed or parsing was repaired.

**Controlled comparison from the frozen study (16 inert fixtures, 20 repeats per engine, commit 1668326):**

| Fixture | Reference verdict | Unified verdict | Interpretation |
| --- | --- | --- | --- |
| 5a-pdf-auto-js-unrelated-attachment | MALICIOUS | SUSPICIOUS | Removes the unsupported inference that a separate attachment is delivered by the script |
| 5b-pdf-auto-js-exports-attachment | MALICIOUS | MALICIOUS | Preserves high severity where the automatic action actually references the attachment |
| 2b-pdf-open-at-page-click-js | SUSPICIOUS | SUSPICIOUS | Overall verdict unchanged, but custom chain analysis correctly keeps the click-only action nonautomatic |
| 3-pdf-escaped-openaction-js | SUSPICIOUS | SUSPICIOUS | Structural inspection handles the selected escaped name that bytes-only signatures miss |

The project measures **indicator handling on inert fixtures**. These verdicts are not ground-truth malware labels and are not sensitivity/recall estimates.

## 4. Flagship technical contribution B: VBA macro call graph

**Problem:** Merely finding an auto-execution keyword and a dangerous keyword *anywhere in the same VBA project* does not prove the auto-executed procedure reaches that behavior.

**Original algorithm (app/engine/vba_chains.py):**
1. Use oletools to extract VBA source from relevant Office containers. This extraction step is reused and attributed.
2. Normalize continuations and split code into bounded procedures. Strip comments and separate literal strings so a procedure name appearing in a comment is not treated as a call.
3. Parse procedure references, literal dispatch such as Application.Run and AddressOf, plus aliases in external declarations. Distinguish demonstrated edges from possible or dynamically unresolved edges.
4. Identify automatic entry points using documented entry-name sources.
5. Run a breadth-first graph search from each entry. Return a concrete call path for linked, no-path only when the source graph is complete, and undetermined for dynamic calls, partial source, or other ambiguous evidence.
6. In app/engine/correlate.py report the result without automatically downgrading a reference HIGH verdict. Source-only analysis cannot rule out VBA stomping or malicious compiled P-code.

**Tests:** tests/test_vba_chains.py includes inert string fixtures covering transitive calls, cross-module calls, comments/strings, cycles, indirect literal calls, possible aliases, dynamic calls, parse errors, and retention of stronger reference findings. No macro content is executed in these tests.

**Why this is not a size rule:** It models potential execution reachability through a directed call graph. The output includes an evidence path and an explicit uncertainty state.

## 5. Evaluation and reproduced findings already recorded

- **Frozen November 7 comparison:** 16 deterministic inert fixtures, 20 trials for each engine on the same Windows development machine. Raw results and matrices: docs/evidence/custom-engine-1668326/. Differences in timing are not independent samples or cloud benchmarks.
- **Offline VM evaluation:** The November 9 study recorded 57 files across two configurations and 114/114 expected scan outcomes; 102 earlier-case outputs matched Windows evidence and 12 C7 case outcomes matched their expected verdicts. See docs/evidence/final-6907929-run2/final-6907929/report.md and docs/capstone-development-history.md. These evaluate specified indicators, not performance on a labelled malicious corpus.
- **Independent reference/real benign cases:** The development history records benign-compatibility tests and external fixtures, including cases where initial SAFE or SUSPICIOUS results revealed incomplete analysis or conservative attachment warnings. External validation exposed new gaps rather than proving universal correctness.
- **Current repository CI baseline:** The November 18 main commit b6774bea has a successful Security engine tests workflow (https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/44382980470). This supports code regression status at that commit, not a new independent-malware validation.
- **Deployment status checked November 20:** Render shows the production Security Engine live at b6774bea and the Conversion Engine live at 482e724. Those facts establish deployment of two services; they do **not**, by themselves, prove every converter route is unbypassably protected. Older dated journal entries that say production integration was not present describe their earlier evidence cutoffs.

## 6. Limitations, constraints and responsible claims

1. Static inspection cannot predict all runtime behavior; VBA P-code may differ from displayed source.
2. Parser repair, encryption and partial coverage are separate from the presence of a detectable indicator. The current decision policy must be considered alongside conversion eligibility.
3. Synthetic cases prove selected logic, not real-world malware precision, recall, or false-negative rates.
4. Genuine-malware testing was not authorized in these evaluations. Keep the production host and public Lab free of active malicious uploads unless all institutional and provider approvals are obtained.
5. Graph extraction is format-specific and resource-bounded; dynamic names, indirect execution and unhandled formats require uncertainty rather than unjustified SAFE claims.
6. Performance findings are environment-specific; the unified engine was generally not faster in the controlled comparisons. Do not claim a speed gain without measurement.

## 7. Demonstration plan (6 to 8 minutes; not yet performed)

1. **Research question:** Explain why keyword co-occurrence overstates risky behavior and why explicit reachability matters.
2. **Show the PDF implementation:** app/engine/pdf_chains.py functions extract(), _actions(), and PdfChains.linked(); then app/engine/correlate.py.
3. **Show test 5a vs 5b:** Open tests/test_pdf_chains.py and the two frozen comparison matrices. Explain why the outcomes differ. Do not call either fixture actual malware.
4. **Show the VBA implementation:** app/engine/vba_chains.py functions parse(), link(), search(), and analyse(); open tests/test_vba_chains.py for linked/no-path/undetermined cases.
5. **Show independent test evidence:** Open the successful CI run and the offline-VM report; distinguish unit tests, controlled experiments and still-unmeasured real-world detection accuracy.
6. **Show real-world application:** Explain that the scanner is deployed with FilesMagic, and distinguish engineering deployment from the academic contribution and from unverified end-to-end guarantees.
7. **Close with limitations:** Explain one failed approach, one correction, and why a claim of universal malware safety would be unjustified.

## 8. Acceptance checklist, with evidence status

| Criterion | Evidence as of November 20 | Remaining human action |
| --- | --- | --- |
| Original substantial analysis implemented | PDF trigger/action graph, VBA call graph, OOXML graph, C7 fields and correlation code exist | Explain source methods, design tradeoffs and code paths directly |
| Reference versus original comparisons | Preserved frozen matrices and VM report | Demonstrate selected cases and explain findings |
| Working tests | Nov 18 main CI successful | Review CI on final academic branch and disclose any failures |
| Written development history | docs/capstone-development-history.md and custom-engine-research-log.md | Confirm personal learning/reflection details and attach mentor feedback |
| Honors poster | Accepted for printing according to November 20 mentor meeting | Present December 3, capture proof, submit required artifacts |
| CSCI 499 grading | Unresolved at meeting; clarification emails sent November 20 | Confirm Daniel/Connie responses and faculty submission mechanism |
| Faculty acceptance | Not yet assessed for final grade | Demonstrate to Dr. Haque and obtain his evaluation |

**Submission status:** This document is a *faculty-review brief*, not an assertion that the Honors submission, reflection, presentation attendance, or faculty grading are finished. If the student cannot independently explain the algorithms, the central mentor requirement is still unmet.

## 9. Primary reproducible source map

- docs/custom-engine-approved-plan-2026-11-06.md: agreed narrow scope, dependency attribution, experimental protocol.
- docs/custom-engine-research-log.md: dated algorithm design, literature/source references, progress and rejected hypotheses.
- docs/capstone-development-history.md: longitudinal research journal, experiments, failures and limitations.
- docs/evidence/custom-engine-1668326/: frozen baseline and unified case matrices.
- docs/evidence/final-6907929-run2/final-6907929/report.md: offline-VM case comparison and isolation findings.
- tests/test_pdf_chains.py and tests/test_vba_chains.py: concrete reproducible examples.
- .github/workflows/security-engine-tests.yml: automated Linux test entry point.
