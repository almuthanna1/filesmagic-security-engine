# Capstone code defense: understand it well enough to explain it
**Prepared:** November 20, 2026  
**Purpose:** Practice for Dr. Haque's original-implementation evaluation. The student must verify understanding rather than memorize a script.

## A. Five-minute opening explanation

"My project addresses the risk of scanning complex PDF and Office documents before conversion. I started with existing scanning libraries, but the original research contribution is not those libraries. The new question I investigated was whether suspicious indicators are actually connected to an automatic execution path. I built analysis that models PDF trigger-to-action relationships and VBA procedure-call relationships. It returns evidence and an uncertainty state rather than treating keywords found anywhere in a file as proof of a particular behavior. I compared the resulting custom unified engine with the original scanner on controlled, inert documents, evaluated it in an offline VM, and recorded both improvements and limitations. The hosted FilesMagic integration is where this research can be applied, not a substitute for the research."

## B. VBA implementation walkthrough (primary defense)

Open: app/engine/vba_chains.py

**Start with the question:** Can an automatic entry procedure reach a risky capability through a chain of calls?

1. **_clean(line)** strips comments and blanks string contents for symbol recognition, but retains literal strings separately for named dispatch. This avoids treating a name inside a comment as a real call.
2. **parse(module, source, problems)** recognizes procedure boundaries, keeps procedure code, identifies module-level declarations, and marks missing End statements or unmatched End as structural problems.
3. **capabilities(code, blanked)** combines oletools' keyword descriptions with context checks to distinguish demonstrated from merely possible risky behavior. Explain exactly what comes from olevba rather than calling this a new parser.
4. **link(procedure, by_name, modules, shadowed)** builds directed edges. A direct Call or module-qualified invocation gives demonstrated evidence when resolvable; a possibly shadowed identifier or ambiguous receiver produces possible evidence; unknown dynamic dispatch is recorded separately.
5. **analyse(modules, problems)** collects parsed procedures, bounds procedure count, builds lookup maps, links graph nodes, identifies entry points and runs search for each.
6. **search(entry, problems)** performs *two graph searches*. First, a breadth-first search follows only demonstrated calls and looks for a demonstrated dangerous capability, returning linked with a reproducible path. If none is found, a second breadth-first search explores possible edges and dynamic/incomplete cases. It reports undetermined when evidence is ambiguous, or no-path when the extracted source can be fully explored without an identified path.
7. **vba_findings()** in app/engine/correlate.py maps linked to the HIGH rule ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY, while no-path and undetermined generate explanatory INFO rules. The reference HIGH warning is never blindly removed.

### Trace these three inert source examples

**Example 1: a demonstrated path**
- AutoOpen calls Prepare; Prepare calls RunTool; RunTool contains a placeholder command-execution keyword.
- The graph has AutoOpen -> Prepare -> RunTool; the first search returns linked and records the path.
- Evidence: tests/test_vba_chains.py, test_related_procedures_establish_a_path_through_transitive_calls.

**Example 2: a dangerous procedure exists but is unrelated**
- AutoOpen displays a message; an unrelated RunTool procedure contains the placeholder command keyword.
- The graph contains no call from AutoOpen to RunTool. The extracted-source conclusion is no-path, not a proof of absolute file safety.
- Evidence: test_an_unrelated_dangerous_procedure_gives_no_path.

**Example 3: dynamic or ambiguous dispatch**
- AutoOpen calls a procedure using a dynamically computed name.
- Static analysis cannot prove the target. Without a separately demonstrated path, the result is undetermined.
- Evidence: test_run_with_a_computed_name_is_unresolved_not_an_execution; test_dynamic_calls_on_the_reachable_part_make_the_path_undetermined.

### Ask yourself before the meeting
1. Why does the algorithm use breadth-first search? (It yields a short concrete trace and terminates under a visited set on cyclic graphs.)
2. What is the difference between linked, no-path and undetermined?
3. Why do comments and quoted strings need different handling?
4. Why can a CallByName or dynamically chosen Application.Run target prevent a confident no-path result?
5. Why does the engine not clear an existing HIGH warning after finding no-path in source? (VBA P-code may differ from source; the process has not proven compiled behavior harmless.)
6. Which functionality is imported? (VBA extraction and keyword/entry-point sources from oletools; NOT the graph model or two-pass search.)

## C. PDF implementation walkthrough (secondary defense)

Open: app/engine/pdf_chains.py and app/engine/correlate.py

**Start with the question:** Does the *specific* automatic PDF action reference the attachment, or do the script and attachment merely coexist?

1. **scan(data)** checks that input is a PDF and wraps object inspection in configured resource limits and error handling.
2. **extract(data)** obtains a parsed object graph with pypdf, then traverses catalog/document structures using a visited set and depth/object budgets. It identifies triggers such as /OpenAction, /AA and /A and distinguishes automatic from click-triggered actions.
3. **_actions(value, owner, budget)** walks the trigger's /Next action sequence. It does not follow an unrelated page link and does not loop infinitely on cyclic references.
4. **_describe(action, where)** describes JS actions, Launch file specifications, attachment-export calls and embedded-document navigation.
5. **PdfChains.linked(chain)** connects an action to an embedded attachment only if that action names it, or the name is computed and the model cannot rule out relevant attachments.
6. **chain_findings() and correlate()** use contextual relationships and safety preconditions to interpret severity. If a parser repaired a document or reference evidence is incomplete, do not suppress a stronger existing indicator.

### The decisive PDF counterexample

| Case | Reasoning | Frozen baseline -> unified |
| --- | --- | --- |
| 5a | /OpenAction runs JS; an attachment exists but is not referenced on the chain | MALICIOUS -> SUSPICIOUS |
| 5b | /OpenAction's JS explicitly exports the attachment | MALICIOUS -> MALICIOUS |

Both are **inert synthetic structure tests**, not real malicious documents. The case comparison is preserved in docs/evidence/custom-engine-1668326/reference/matrix.md and unified/matrix.md.

### Why does this research matter?

An indiscriminate rule may report a severe, unsupported execution relationship for legitimate documents with unrelated features. A contextual graph makes the *reason* for a warning testable, while preserving conservative handling where the relationship is unclear. It improves a narrow question of interpretability/selected indicator classification; it does not prove broad malware-detection performance.

## D. Explain one research failure clearly

**Failed assumption:** Initial detection treated co-occurring automatic PDF JavaScript and an attachment as though the script delivered the attachment. The controlled 5a case showed the problem.

**Correction:** Build one action graph for each trigger, link only the attachments reached on that graph, and keep evidence unchanged if the parser's coverage is insufficient.

**Verification:** The frozen study includes both the negative case (5a) and the positive control (5b). The two cases differ exactly where the connection exists.

**Other truthful limitations:** YARA-X rule reuse did not materially improve latency in the measured experiment; some PDF coverage cases uncovered false SAFE assumptions, leading to later fail-closed changes. The unified engine may be slower than the reference due to additional analysis.

## E. Reproduction commands for the student to run in a trusted checkout

The repository uses Python and pinned dependencies. Running these locally requires an environment that can install the repository's requirements; they have not been rerun as part of preparing this guide.

    python -m pytest -q tests/test_vba_chains.py tests/test_pdf_chains.py tests/test_correlate.py tests/test_word_fields.py

For the full CI suite, see .github/workflows/security-engine-tests.yml and the latest successful main-branch workflow run (November 18). Use GitHub Actions on the academic branch for a verified new run.

For the frozen experiment, follow docs/evidence/custom-engine-1668326/README.md exactly. Do not compare new timings to the historical figures as though they were measured on the same machine and warm/cold state.

## F. Ten rapid-review questions, with answer key

1. **What is your original contribution?** Contextual static graph analysis of PDF action chains, VBA procedure calls, OOXML activation and Word fields, plus explicit evidence correlation; not the upstream parsers.
2. **What is the input?** Untrusted PDF/Office bytes; format-specific parsers extract structured facts under explicit limits.
3. **What does the VBA graph represent?** Nodes represent procedures; edges represent demonstrated or possible calls; entry nodes represent auto-execution.
4. **Why two searches?** To identify a demonstrable path before considering less certain possible paths, then distinguish inconclusive evidence from absence of a path in the extracted source.
5. **What happens with cycles?** Visited sets prevent endless traversal.
6. **What is a PDF action chain?** A trigger and only the action sequence it starts, including /Next, not unrelated actions elsewhere in the document.
7. **How do 5a and 5b differ?** The automatic script in 5b references the embedded attachment; the one in 5a does not.
8. **Can the system prove a file is harmless?** No. It reports selected detectable indicators, known coverage, and uncertainty.
9. **Why not write the entire parser yourself?** Proven parsers safely handle intricate container specifications; the original research question is reachability and explainable classification. Cite and attribute everything reused.
10. **What would you do next?** Assess performance against an independently labelled, approved dataset; improve bounded coverage and production gate verification. Do not claim those experiments have been completed.

## G. Faculty review closing statement

"The contribution I want evaluated is the original detector logic and the controlled evidence for it. I can explain the graph structures, input normalization, risk rules, and uncertainty conditions. I also know what this work cannot prove. The production use makes the work practical, but my capstone research is the analysis method and its measured behavior."

**Student verification required:** If you cannot explain any section directly from the source, mark it as needing study and address it before describing the project as complete. This document is a study guide, not evidence of personal mastery.
