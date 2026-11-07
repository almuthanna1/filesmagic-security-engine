# Poster draft (first version, for review with Dr. Haque)

**Working title:** Correlating Evidence Along Execution Paths: An Explainable Document-Security Engine for PDF and Office Files

Almuthanna Shihab · Supervisor: Dr. Nur Imtiazul Haque · NIU CSCI 499 Honors Capstone · November 2026

> Format note: the repository records no NIU poster specification (size, template, logo use,
> minimum type size). Confirm these with NIU and Dr. Haque before layout. Every number below comes
> from the frozen evaluation (`docs/evidence/custom-engine-1668326/`) through `evaluation.poster`;
> figures are in `docs/poster/figures/` as SVG (vector, for PowerPoint) and PNG.

---

## 1. Introduction and motivation

Documents are a common way to deliver attacks: a PDF can run JavaScript when it opens, and a Word
file can load a remote template or run macros. FilesMagic converts uploaded documents, so it scans
them first, in an isolated worker, with three established tools (YARA-X signatures, pypdf, oletools)
plus its own structural detectors.

Those scanners report **indicators**: "this file contains JavaScript", "this file has an
attachment", "this macro project can start a program". They do not say whether the indicators are
**connected**. Combining unrelated indicators turns benign files into alarms; ignoring their
connection loses the evidence an analyst needs. Our question: *does an indicator lie on a path
that actually executes or loads it?*

## 2. Research objectives

1. Model the execution and loading paths of PDF and Office documents (triggers, action chains,
   call graphs, relationship references) from their file-format specifications.
2. Correlate scanner findings only when they share a path, and explain every verdict with that path.
3. Never lower a verdict on incomplete or uncertain analysis (fail closed).
4. Measure the effect against the existing four-scanner engine on the same inputs, including latency.

## 3. Methodology and architecture

**Figure 4 - Approved architecture** (`fig4-architecture.svg`). Caption: *Redrawn from the approved
FigJam board (node 12:134): the same 5 sections, 17 components and 20 connections; only spacing and
type size changed for print. Implemented as of November 6: sections 01, 02 (without the Format
Router), 03, 04 and 05. The Format Router is approved but deliberately not built yet: routing on
untrusted magic bytes needs an isolation review first.*

- **Isolation (reused, unchanged).** Each scan runs in a fresh worker process; on Linux a user and
  network namespace, dropped capabilities, resource limits and an audit hook. Errors, timeouts and
  missing isolation give UNABLE_TO_SCAN, never SAFE. Linux CI runs all 28 isolation tests.
- **Reference baseline.** The existing engine: YARA-X, PDF, Office and custom (C1, C4-C6) scanners.
- **Unified engine.** The same four scanners, plus four engine components, plus correlation:

| Component | Question it answers |
|---|---|
| PDF action chains | Which trigger starts which actions, and which embedded file do they use? |
| Refined signature | Do the bytes *prove* an /OpenAction or /AA is not automatic? |
| VBA call graph | Can an automatic macro reach a dangerous operation through its calls? |
| OOXML activation graph | Does a part Office loads reference this relationship, and when is it used? |

- **Evaluation.** 16 inert synthetic fixtures (ground truth BENIGN: each carries a structure, not
  malware) in 5 scenarios, scanned 20 times by each engine through the real worker on one machine.
  Detection is counted per fixture (n = 16); the 20 trials measure timing only.

## 4. Original contributions

**Reused (third-party):** YARA-X (matching engine), pypdf (PDF parsing), oletools/olevba (VBA
extraction and keyword analysis), defusedxml. **Reused (prior project work):** the isolated
worker, the four reference scanners, the custom OOXML reader (C4-C6), the evaluation harness.

**Original in this work:**

1. **PDF action-chain correlation.** A chain is a trigger plus its `/Next` actions only (ISO 32000-1
   12.6.2). An escalation requires the automatic script and the embedded file on the *same* chain.
2. **Count-and-subtract signature refinement.** A YARA-X rule that discounts only the /OpenAction
   and /AA occurrences its bytes prove non-automatic, so it never fires where the original does not.
3. **VBA call graph with demonstrated vs. possible evidence.** Three outcomes (linked, no path,
   undetermined); keywords that do not by themselves show execution (`Run`, `Shell` inside
   `WScript.Shell`, `shell32`, `vbHide`) count only as possible.
4. **OOXML activation graph.** A relationship counts as used only when a loaded part references its
   Id; the referencing element (ISO/IEC 29500) says whether it is used on open, on update, on click
   or when an object is activated.
5. **A documented, fail-closed correlation policy.** Every replacement has a precondition; macro
   and Office relationship findings are qualified, never removed.

## 5. Evaluation results

**Figure 1 - Detection comparison** (`fig1-detection-matrix.svg`). Caption: *16 inert fixtures, 20
identical runs each per engine. One verdict differs (5a); the other 15 are unchanged, with evidence
added, superseded or qualified.*

**Figure 2 - Why 5a and 5b differ** (`fig2-pdf-correlation-5a-5b.svg`). Caption: *Same trigger, same
attachment; only 5b's script names the attachment. The reference engine rates both MALICIOUS
(PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD, HIGH); the unified engine keeps 5b MALICIOUS
(ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT, HIGH) and rates 5a SUSPICIOUS (ENGINE_PDF_AUTO_CHAIN_SCRIPT,
MEDIUM).*

**Figure 3 - Latency** (`fig3-latency.svg`). Caption: *320 scans per engine (16 fixtures x 20).
Whole scan p50 555.5 ms (reference) and 567.6 ms (unified), p95 629.4 and 629.1 ms; detection work
inside the worker p50 2.2 and 3.2 ms. Worker start-up is over 99% of the time.*

Demonstrated on these fixtures:
- **One unjustified escalation removed:** 5a, MALICIOUS to SUSPICIOUS, while 5b stays MALICIOUS.
- **False "automatic" claims removed:** 3 rule hits on the two click- and keystroke-script fixtures
  (2, 2b) in the reference engine, 0 in the unified engine; every true automatic claim (2c, 3, 4,
  5a, 5b) is kept.
- **Explainable evidence:** findings name the path, e.g. `catalog /OpenAction: JavaScript (object 7 0)
  (exports 'f')`, and `package -> word/document.xml -> word/settings.xml -> attachedTemplate rId1 ->
  https://template.example.invalid/normal.dotm`.
- **Office relationships qualified, not removed:** the same template relationship is *confirmed*
  when settings references it (6c) and marked *use not demonstrated* when nothing does (6b).
- **Determinism and completeness:** all 640 scans returned identical findings per fixture; no
  scanner failed; one analysis was undetermined (7: the macro part is a placeholder, not a VBA project).
- **Latency:** detection work rose about 1 ms (p50 2.2 to 3.2 ms). The whole-scan p50 difference
  (+12 ms) is within run-to-run variation: per fixture it ranged from -14.6 to +51.6 ms, and 5 of 16
  fixtures were faster with the unified engine. No latency improvement is claimed.

Unchanged, and still potential false positives in both engines: the form-keystroke and click
scripts (2, 2b: any JavaScript is MEDIUM by the PDF scanner's policy) and the embedded objects
(6e, 6f: the Office scanner rates any embedded OLE object LOW).

## 6. Limitations and future work

- **Synthetic, benign fixtures only.** The results show how indicators are classified, not malware
  detection accuracy or real-world false-positive rates. Live samples need the documented
  institutional approvals and the offline VM.
- **Macros:** the call graph analyses source code. Office may run compiled P-code instead (VBA
  stomping), which olevba checks only for files on disk; the isolated worker writes none. So the
  engine never lowers a macro verdict. The macro analysis is unit-tested on inert source strings, not
  measured on documents.
- **Office behaviour is taken from the specification,** not observed: whether external content is
  fetched depends on the application (Office blocks it by default in Excel and PowerPoint; files
  from the internet open in Protected View).
- **Static analysis:** computed JavaScript and VBA names are not followed; XFA, Word field codes
  (INCLUDEPICTURE, LINK) and embedded documents are not analysed recursively.
- **Latency** was measured on one Windows laptop without Linux isolation active.
- **Future work:** Word field codes (C7); a format router reviewed for isolation; a labelled benign
  and malicious corpus in the offline VM.

## 7. References and attribution

- ISO 32000-1:2008, *Document management - Portable document format - Part 1: PDF 1.7* (sections
  7.3.5, 7.5.7, 7.9.6, 12.6).
- ISO/IEC 29500 / ECMA-376, *Office Open XML File Formats*, Parts 1 and 2; Microsoft Learn Open XML
  SDK reference: AttachedTemplate, Blip, OleObject.
- Microsoft Support: "Block or unblock external content in Office documents"; "What is Protected View?".
- Adobe, *Acrobat JavaScript API Reference* (Doc.exportDataObject).
- MITRE ATT&CK T1221, Template Injection.
- VirusTotal, YARA-X 1.21.0 (BSD-3-Clause). py-pdf, pypdf 6.19.0 (BSD-3-Clause). P. Lagadec,
  oletools 0.60.2 (BSD-2-Clause; uses pcodedmp, GPL-3.0). defusedxml 0.7.1 (PSF-2.0). olefile 0.47
  (BSD-2-Clause). msoffcrypto-tool 6.0.0 (MIT).

Acknowledgement: AI-assisted development (Claude Code) under the supervisor's guidance; every
algorithm, test and measurement was reviewed and is reproducible from the repository.
