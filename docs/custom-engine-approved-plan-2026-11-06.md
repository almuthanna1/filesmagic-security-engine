# FilesMagic Custom Security Engine: Approved Architecture and Implementation Research

**Meeting:** Dr. Nur Imtiazul Haque, November 6, 2026  
**Poster deadline:** November 18, 2026  
**Development base:** `security/malware-research-hardening` at `c8bf8dd56baf9b9e88b4173047ef23fb1c7b31ca`  
**Status:** Architecture direction approved; proposed refinements and algorithms are **not yet implemented or benchmarked**.

## Research objective

Implement a focused, explainable, independently evaluable document-security pipeline for PDF and Office documents. Reuse permissible parsing or matching components from established projects while adding original, demonstrable detection or latency improvements. **This is not a replacement for a general-purpose antivirus product.** Evaluate a deliberately limited set of 5–8 threat-indicator cases rather than claiming universal malware coverage.

## Existing code, not new claims

- `app/scanners/yarax.py`: YARA-X matching; `app/rules/filesmagic.yar`.
- `app/scanners/pdf.py`: custom structural analysis powered by `pypdf`.
- `app/scanners/office.py`: custom structural analysis using `oletools`, `olefile`, Python `zipfile`, `defusedxml`, and `msoffcrypto-tool`.
- `app/scanners/custom/`: already implemented C1 PDF unnecessary hex-escape name detection; C4–C6 OOXML declaration/relationship/ZIP anomaly indicators; original PDF syntax and OOXML readers.
- `app/worker.py`: hardened per-request isolated process and time/resource controls.
- `evaluation/benchmark.py`, `evaluation/evaluate.py`, `evaluation/README.md`: existing evaluation machinery and defined metrics.
- `docs/malware-research-readiness.md`: hosted live-malware testing is **BLOCKED** pending authorization and safeguards. Do not relax this restriction.

Keep existing scanners as independent reference baselines; build the new unified candidate separately. No production changes or deployments are authorized by this plan.

## Verified official sources and bounded reuse

1. **YARA-X**, project docs: https://virustotal.github.io/yara-x/docs/api/python/ ; upstream: https://github.com/VirusTotal/yara-x ; BSD-3-Clause license at https://github.com/VirusTotal/yara-x/blob/main/LICENSE . The Python API supports compiling reusable rules, scan timeouts, match limits and `fast_scan`, which may omit later occurrences. Reuse the library/API and curate new rules; do not claim the Rust matching engine is original.
2. **pypdf**, security docs: https://pypdf.readthedocs.io/en/stable/user/security.html ; configuration limits: https://pypdf.readthedocs.io/en/latest/modules/configuration.html ; source/license: https://github.com/py-pdf/pypdf . Reuse the parser with bounded decompression; contribute original contextual PDF evidence checks and coverage reporting, not a claim of writing a PDF parser from scratch.
3. **oletools**, `olevba` docs: https://github.com/decalage2/oletools/blob/master/oletools/doc/olevba.md ; repository: https://github.com/decalage2/oletools ; license: https://github.com/decalage2/oletools/wiki/License . `olevba` extracts/decompresses VBA and recognizes auto-exec and obfuscation. Reuse authorized extraction and develop our own transparent relationships/correlation or selective-analysis logic; record every imported code fragment and its original license.
4. **OOXML format**, Microsoft: https://learn.microsoft.com/en-us/office/open-xml/about-the-open-xml-sdk . Modern Office documents are ZIP/part/relationship packages. Use documented format structure to implement new checks.

Before copying upstream source code, audit all licenses, transitive/third-party inclusions, attribution requirements and pinned versions. Do not upgrade dependencies casually. Imported components and original contributions must be separately attributed in the poster.

## Candidate MVP hypotheses (must be tested)

- **Detection:** normalize PDF name escapes and inspect context within compressed/object streams so an innocuous-looking byte-level signature cannot bypass selected indicators. C1 already covers some of this; extend only where an independently demonstrated gap exists.
- **Detection:** correlate an active PDF name or script with the **same** automatic action chain, rather than escalating unrelated features found elsewhere.
- **Office:** combine C4–C6 original structural indicators with extracted macro and external relationship facts. Distinguish an ordinary hyperlink or legitimate macro from an auto-load or execution-relevant chain; no false proof of malware.
- **Latency:** profile per-stage wall time and worker startup; test a format-aware router, compiled-rule reuse, bounded selective parsing and avoidance of duplicate ZIP reads. Do not call an optimization faster without matched before/after measurements. YARA-X fast scan can reduce match detail, so verify evidence requirements before enabling it.
- **Reliability:** fail closed on parser errors, timeouts, partial coverage and unavailable isolation. A 'SAFE' verdict does not establish absence of malware.

## Seven initial test cases (synthetic/inert until approvals)

1. Normal benign PDF without active elements.
2. Benign PDF containing legitimate form JavaScript; evaluate false positives.
3. Inert PDF with `/J#61vaScript` style unnecessary name escapes.
4. Inert PDF with relevant names in a compressed object stream.
5. Inert PDF with automatic action and embedded-file/launch **structural indicators**, not an executable payload.
6. Benign OOXML with ordinary hyperlink vs inert external-template/relationship indicator.
7. OOXML with intentionally inconsistent macro declaration or malformed ZIP metadata; safe fixture, never execute macros.

For each: ground-truth classification (`BENIGN` or `SECURITY_TEST` where appropriate), detection rationale, scanner-by-scanner verdict, rule IDs, completeness, latency, and known limits. Synthetic tests demonstrate **indicator handling**, not recall on real malware. Use actual malicious samples only if institutional/hosting authorization and the existing VM containment gates are documented as satisfied; never upload genuine samples to Render, Vercel, GitHub or the public Lab.

## Quantitative evaluation

Use the same dataset, same machine, same warm/cold state, repeated trials, preserved full results, and fixed versions. Compare reference scanners individually, the existing four-scanner aggregate, and the new custom candidate. Show per-case coverage, benign false positives, unable-to-scan, total wall time, per-stage latency, p50/p95 and reproducibility. Compute precision/recall only for independently labeled real samples when approved; do not compute malware accuracy from `SECURITY_TEST` fixtures.

## Teach-as-you-build protocol for Claude Code

For each small step:
1. **SOURCE:** cite the exact official docs/repository lines being used and identify prior vs original code.
2. **TEACH:** explain the threat mechanism and design in plain English, including why each dependency or function is used.
3. **BUILD:** implement one bounded module and tests on this feature branch.
4. **VALIDATE:** run relevant tests and Linux CI where available; record observed evidence and any failure.
5. **REVIEW:** explain exactly which files/functions changed, and quiz the student with 2 short comprehension questions.
6. **COMMIT:** checkpoint with a descriptive commit and update the research log.
Never silently change the original baseline, isolation requirements, live services, or the evidence protocol.

## Work order

- **Nov 6–9:** verify references/versions/licenses; select 5–8 cases and hypotheses; measure current baseline; document the quarantine example and learning notes.
- **Nov 10–13:** implement only priority signature/PDF/Office improvements with synthetic fixtures and unit tests.
- **Nov 14–16:** integrate evidence correlation and isolated runner; run controlled comparisons and plot actual results.
- **Nov 17:** share poster PowerPoint draft with Dr. Haque for comments, finish proofreading.
- **Nov 18:** submit compliant NIU poster with verified results, disclosed limitations and attribution.

This document is a plan, not a claim of completed implementation.
