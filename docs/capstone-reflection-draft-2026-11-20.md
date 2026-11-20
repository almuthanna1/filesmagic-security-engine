# CSCI 499 Honors Capstone: Reflection paper (DRAFT)
**Student:** Almuthanna Shihab  
**Project:** FilesMagic Security Engine  
**Mentor:** Dr. Nur Imtiazul Haque  
**Draft prepared:** November 20, 2026

> **Student review required.** This is an approximately 750-word first-person *draft* derived from the project history, not a submitted reflection or evidence that the student personally mastered every concept. Confirm that each learning statement accurately reflects your experience, and replace the five provisional headings with the exact Honors Blackboard rubric headings before submitting.

## 1. Project purpose and motivation

My capstone project explored how to inspect potentially unsafe documents before a file-conversion system processes them. The project grew out of FilesMagic, a file-conversion application I developed. File converters accept documents from users who may be unknown to the service. Even ordinary formats, such as PDFs and Microsoft Office documents, can contain active features, embedded files, external references, macros, and malformed structures. I wanted to understand those risks and design a security component that could identify selected warning signs before conversion.

The original idea was broad: combine multiple security tools to check files and return an understandable result. As the work progressed, I narrowed the academic research question. Rather than assuming that a suspicious keyword proves malicious behavior, I wanted to examine *relationships* between actions. An automatic PDF script and an attachment should not automatically be treated as a connected threat unless the script actually references that attachment. A similar distinction applies to Office macros and the procedures they call.

## 2. Development process and original work

I developed a separate Security Engine using Python and FastAPI and studied established technologies such as YARA-X, pypdf, and oletools. Those libraries handle important tasks including pattern matching and format parsing. I also worked on original analysis code that goes beyond calling the libraries: PDF action-chain inspection, VBA procedure-call graph analysis, Office document relationship analysis, Word field-code inspection, and rules for correlating evidence.

For PDF files, the custom analysis models the actions that follow specific triggers. It distinguishes automatically triggered actions from user interactions and traces which attachments are referenced by each action chain. For VBA, the custom code identifies procedures and builds call relationships starting at known automatic-entry points. It distinguishes confirmed paths from uncertain or incomplete paths, instead of treating all functions in one project as necessarily connected.

I wrote and refined tests using harmless synthetic structures, preserved baseline comparisons, and documented the implementation in a research log. The research method became just as important as the application: I needed to understand what each algorithm was actually proving and what it could not prove.

## 3. Obstacles, changes, and problem-solving

One practical obstacle was the cost and complexity of running a heavyweight antivirus engine. I initially considered ClamAV, but its resource requirements conflicted with the intended hosting environment. I changed direction toward a lighter combination of signatures and document-aware structural analysis.

I also learned that a scanner can produce a technically valid result while its interpretation is misleading. Early PDF logic raised an overly severe finding when automatic JavaScript and an unrelated attachment appeared in the same file. I addressed that problem by examining which actions actually referenced an attachment. Further testing exposed issues involving incomplete PDF coverage, parser repairs, and benign files with features that could appear suspicious. These findings required corrections, regression tests, and more cautious language in the results.

Creating an isolated testing environment introduced additional challenges. The project used a disconnected Ubuntu virtual machine, controlled file transfers, process restrictions, and AppArmor. Testing those controls was important because security tools themselves process potentially hostile inputs.

## 4. Results and what I learned

The work produced a running analysis service, a browser-based demonstration interface, multiple original contextual detection modules, and automated tests. A frozen comparison used inert PDF and Office fixtures to compare the reference scanner and the custom unified engine. An offline VM study checked 57 inputs using two engine configurations and recorded 114 expected outcomes. These were reproducible checks of selected detection behavior, not a measurement of accuracy against a representative collection of real malware.

The central technical lesson I take from the project is that evidence needs context. Detecting a feature is different from establishing that a particular execution path can reach it. I also learned to distinguish a positive finding from missing coverage. A file cannot be called harmless simply because the configured scanners did not report a known indicator, especially if a parser did not inspect all relevant content.

The evaluation taught me to preserve negative results and failed assumptions rather than reporting only successful tests. A measured optimization that does not improve performance is still a useful research result.

## 5. Broader value and next steps

The work connects academic learning with a real software problem. Document-conversion services, schools, and small businesses often handle files they did not create. An explainable security system can help users understand why a document raises concern and help developers make more cautious processing decisions. However, I cannot claim that my engine detects every type of malware or makes uploads completely safe.

The project also reinforced the value of transparent software engineering: keeping original algorithms separate from third-party components, documenting limitations, and testing in a controlled environment. My next steps would include further verification of the production security gate and, with appropriate permissions and a carefully labelled dataset, evaluating detection performance on a broader range of documents. Above all, the capstone showed me that a working product is not the same as a well-supported technical conclusion.

---
**Submission status:** Draft only. Verify the exact five required sections, word count, assignment deadline, and personal truthfulness before final submission.
