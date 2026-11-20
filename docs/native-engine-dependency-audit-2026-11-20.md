# Native-only detector research: dependency and ownership audit
**Date:** November 20, 2026  
**Baseline:** `main` commit `b6774bea199f13170a4dfb144048f7d63f59b859`.  
**Purpose:** Distinguish author-owned analysis from third-party scanners and parsers, and define research steps for an experimental, narrowly scoped native-only detection mode. **No production migration is authorized by this document.**

## 1. Three distinct meanings of "custom"

1. **Original detector intelligence:** Authored algorithms for identifying evidence, correlating execution paths, and classifying specific document behaviors, while reusing trusted document parsers.
2. **Third-party-free detection layer:** No YARA-X, pypdf, oletools, olefile, or msoffcrypto-tool in the experimental detector execution path. Python standard-library ZIP/zlib/regex support remains acceptable. Unsupported formats and ambiguous coverage fail closed. This is *not* equivalent to matching the full reference engine's format coverage.
3. **Entirely dependency-free deployed product:** Would also require replacing FastAPI, Pydantic, cryptography, hardened XML parsing, React/Next.js, language runtime and operating system services. Not a defensible or necessary capstone objective. In particular, never implement original cryptographic primitives for a production security gateway to meet an authorship quota.

The **November 6 approved research plan** explicitly permits reusing parsing/matching libraries while developing original, demonstrable detection contributions. An additional native-only experiment can increase the educational value, but is not the baseline requirement nor automatically proof of higher quality.

## 2. Scanner composition (code-verified)

The **reference** roster in `app/scanners/__init__.py` is four scanners:
- `YaraXScanner`: third-party `yara_x.Compiler`/`Scanner` engine with FilesMagic-authored rule files in `app/rules/filesmagic.yar`.
- `OfficeScanner`: FilesMagic structural findings using external `oletools.olevba`, `oletools.oleobj`, `olefile`, `msoffcrypto`, `defusedxml`, and stdlib `zipfile`.
- `PdfScanner`: FilesMagic PDF-specific heuristics on third-party `pypdf` reader and object model.
- `CustomScanner`: FilesMagic-authored PDF byte lexer and OOXML package logic, using Python `zipfile`/`zlib` and external `defusedxml` for XML.

The **unified** roster in `app/engine/__init__.py` contains the four reference scanners **plus**:
- `EngineSignatures`: one original refined PDF signature, still executed by external YARA-X.
- `PdfChainScanner`: original graph traversal and evidence linking, based on pypdf object parsing.
- `PdfIntegrityScanner`: original coverage/health assessment atop pypdf decoding.
- `VbaChainScanner`: original source-code procedure and call graph, based on olevba source extraction, automatic entry names, and keyword analysis.
- `LinkScanner`: original OOXML activation and relationship graphs, using the authored package reader with stdlib ZIP and defusedxml.
- `FieldScanner`: original Word field assembly and classification, using the authored package reader with defusedxml.

Original post-scan decisions are in `app/engine/correlate.py`, `app/decision/__init__.py`, and the worker's logic in `app/worker.py`. Scanner class creation in `app/engine/__init__.py` is not itself a new scanning method.

## 3. External-component replacement inventory

| External component | Pinned version (`requirements.txt`) | Actual role | Specific replacement for experimental detector | Knowledge needed | Priority |
| --- | --- | --- | --- | --- | --- |
| YARA-X, `yara-x` | 1.21.0 | Compiles and executes YARA rules over raw bytes, including offsets, counts, strings, case-insensitive/wide strings, regex, integer reads and Boolean rule conditions; used in both reference and custom signatures | Port the 9 curated reference rules and 1 refined engine rule to explicitly authored Python detector functions, or implement a narrowly scoped, rigorously specified matcher; retain finding IDs and metadata | Binary signatures, byte offsets and endianness, bounded regex, finite-state matching, testing timeouts/match caps | High, smallest tractable first |
| `pypdf` | **7.0.1** | Parses indirect objects, cross-reference entries, object streams, dictionaries/name trees, stream filters and encryption status; read by baseline PDF analysis and new action-chain/integrity/attachment modules | Extend `app/scanners/custom/pdf_syntax.py` from lexical inspection to a bounded *security-relevant* object resolver with explicit incomplete-coverage statuses | ISO 32000: object grammar, xref tables/streams, incremental updates, stream decoding, /Filter and object streams, PDF encryption metadata, limits and repair behavior | High research value, high engineering risk |
| `oletools` / `olevba` | 0.60.2 | Extracts VBA macro source, handles source decompression, supplies autoexecution patterns and suspicious keyword analysis | Develop a documented VBA project/module extractor, source decompressor, original entrypoint/keyword tables; feed source into existing authored call graph | MS-OVBA compressed source chunks and module metadata, MS-VBAL syntax, code pages, statement normalization, VBA dynamic dispatch | High research value |
| `olefile` | 0.47 | Reads legacy OLE/CFB streams for .doc/.xls/.ppt and embedded VBA projects | Bounded CFB reader with FAT/MiniFAT chains, directory entries, sector bounds, stream extraction | MS-CFB header, allocation tables, chains, mini streams, malformed chain detection | Prerequisite for VBA extraction |
| `msoffcrypto-tool` | 6.0.0 | Detects Office encryption and lack of inspectable contents | Inspect relevant container/metadata flags; explicitly report encrypted or undecodable inputs rather than attempting decryption | MS-OFFCRYPTO format markers and container typing; distinguish detection from cryptographic decryption | Moderate |
| `defusedxml` | 0.7.1 | XML reader configured to reject DTD/entity hazards in Office, OOXML, C2PA, Word fields | Retain as trusted infrastructure for the academic experiment **or** implement a carefully bounded secure stdlib parser with independent hostile-XML tests; do not hand-roll a full XML parser | XML well-formedness, DTD/entity risks, streaming parsing, namespaces, work budgets, fuzzing | Low replacement value |
| `pcodedmp` | 1.2.6 | Transitive oletools dependency; not directly called by FilesMagic code in the analyzed paths | No replacement needed to remove a direct engine call; it disappears from the detector dependency graph when oletools is removed. VBA P-code interpretation remains an **uncovered capability**, not a solved problem. | VBA P-code vs textual source; stomping limitations | Disclose only unless scope expands |

**Version drift:** The dated research log cited pypdf 6.19.0, but the current deployed-code repository's `requirements.txt` pins 7.0.1. Re-verify dependency versions and evaluation baselines before new comparisons. Do not silently claim the historical evidence was produced with version 7.0.1.

## 4. Already custom components to retain, not rewrite

| FilesMagic source | Original logic | Foundation |
| --- | --- | --- |
| `app/scanners/custom/pdf_syntax.py` | PDF name-token lexer, escaped-name reconstruction, bounded object-stream inspection and coverage signals | Python `re`, `zlib` |
| `app/scanners/custom/pdf.py` | C1 active-name obfuscation and incomplete coverage findings | Authored PDF lexer |
| `app/scanners/custom/ooxml_package.py` | OOXML part/relationship resolution, metadata bounds and package reading | Python `zipfile`, `defusedxml` |
| `app/scanners/custom/ooxml.py` | C4–C6 OOXML declaration, relationship and ZIP inconsistencies | Authored package reader |
| `app/engine/pdf_chains.py` | Directed PDF action-chain traversal, automatic-trigger classification, attachment correlation | External pypdf object model |
| `app/engine/pdf_integrity.py` | PDF analysis coverage and parser repair findings | External pypdf object model |
| `app/engine/pdf_attachments.py` and `c2pa.py` | Bounded inspection of selected ODF/C2PA attachment structures; does not cryptographically verify C2PA signatures | pypdf for PDF attachment stream, stdlib ZIP, defusedxml |
| `app/engine/vba_chains.py` | VBA procedure identification, call graph, demonstrated/possible edges, linked/no-path/undetermined output | External oletools macro source and keyword tables |
| `app/engine/ooxml_links.py` | OOXML activation and load path analysis | Authored package reader, defusedxml |
| `app/engine/word_fields.py` | Field reconstruction across XML runs and nested fields, target classification | Authored package reader, defusedxml |
| `app/engine/correlate.py` | Custom reference/unified evidence reconciliation under preconditions | External reference findings still present |
| `app/decision/__init__.py` and `app/worker.py` | Finding severity, incomplete coverage, fail-closed/consent logic; process and Linux namespace/capability protections | Python/OS interfaces, Pydantic data models |

The reference `app/scanners/pdf.py` and `app/scanners/office.py` contain **FilesMagic-authored detection rules** that depend on external parsers. Do not count all of their detection logic as third-party code.

## 5. Other third-party software is infrastructure, not detector intelligence

- `fastapi`, `starlette`, `uvicorn`, `python-multipart`: web request and ASGI API plumbing.
- `pydantic`, `pydantic_core`: request/response and internal report validation.
- `cryptography`: Ed25519 token/receipt signature verification and signing in `app/auth.py`, `app/receipts.py`. **Do not replace with amateur cryptography.**
- `next`, `react`, `react-dom`: Security Lab UI, not file scanners.
- `pytest`, `httpx`: development/test tools, not production detection.
- `zipfile`, `zlib`, `re`, `hashlib`, `struct`, `xml.etree`, Linux namespaces/AppArmor: Python standard-library and operating-system facilities. Using them does not mean a new third-party malware engine was borrowed.
- Remaining requirements include transitive support packages. They must be reviewed with a generated dependency tree before asserting a no-third-party-runtime build.

A zero-external-**detector** claim is different from a zero-dependency-**product** claim.

## 6. Research and implementation sequence (do not disrupt production)

**Stage 0: Freeze reference and prove provenance**
- Pin main commit, lockfiles and rule IDs; preserve a fixed inert synthetic/benign corpus and outputs.
- Add a separate research-only engine identifier such as `native-research`. Never substitute it for `unified` in production or weaken security receipts.
- Establish explicit comparison criteria: matching findings, full coverage, fail-closed behavior, memory and time budgets, regression suite, and student explanation.

**Stage 1: Replace YARA-X's *execution*, not the research question**
- Port only the rules actually used today: nine in `app/rules/filesmagic.yar` and one refined rule in `app/engine/rules/pdf.yar`.
- Implement deterministic, bounded operations for literal/wide/case-insensitive matching, regex, offset constraints, match counts, and `uint16/uint32` at fixed/dynamic offsets. Preserve each finding's rule ID, severity and explanation.
- Compare to reference on positive, negative, malformed, adversarial and randomized inert byte inputs. Do not assert generic YARA-language compatibility.
- **Educational deliverable:** explain a binary-offset condition and a regex/match-cap guard.

**Stage 2: Own a focused VBA extraction path**
- Implement a bounded MS-CFB stream reader and directory chain validation; support VBA module containers found in legacy OLE or `vbaProject.bin` within OOXML.
- Implement MS-OVBA module compression decoding and code-page-aware source extraction. Start with unencrypted, conventional VBA projects and explicitly flag XLM, compiled P-code and malformed/unknown records as incomplete.
- Replace olevba's autoexec/keyword tables with independently specified, documented capability rules. Reuse the existing authored directed call graph; run tests for linked, no-path and undetermined cases.
- **Educational deliverable:** trace an actual inert macro-bearing document through CFB allocation -> compressed module -> recovered VBA source -> graph -> finding.

**Stage 3: Own the security-relevant PDF object model**
- Extend the authored byte lexer to parse the cross-reference structures, indirect object lookup, name trees and /Next references needed by the existing chain detector.
- Add stream decode and PDF resource controls; classify encrypted, unsupported, repaired and ambiguous structures as incomplete. Do not silently classify unsupported PDF 2.0 or unknown filters as SAFE.
- Compare cases 5a/5b, escaped names, object streams, incremental updates, bad xrefs and attachment coverage against pypdf-based results.
- **Educational deliverable:** show how the same PDF file bytes resolve to an automatic trigger/action graph and justify every limitation.

**Stage 4: Evaluate rather than merely remove imports**
- On the *same* controlled files, compare reference, current unified and new native research detector.
- Report per-case findings, correctness against expected indicator outcomes, false positives on labelled benign files, unable-to-scan and missing coverage, time/memory and isolation.
- Do not calculate real-malware precision or recall from inert fixtures. Record where the native engine supports fewer formats than current unified.
- Have the student defend every authored parser and detector; disclose AI assistance according to NIU policy.
- Keep review branch independent and run CI before any future production proposal.

## 7. The minimum viable academic extension

A credible narrow improvement is a **native VBA source-extraction chain** plus documented original call-graph behavior, or a **native PDF action-object resolver** atop the existing lexer, with a negative and positive controlled example and defensible coverage. A quick YARA rule replacement is a useful first parity exercise but, alone, might not satisfy the mentor's demand for a substantial research algorithm.

**Feasibility:** Reimplementing the entire YARA-X + PDF + OLE/VBA parsing capability while preserving production safety within a single day is not realistic. A narrow demonstrable native detector by the December 4 mentor meeting is more plausible, but it still requires actual tests, safe unknown handling and personal code comprehension.

## 8. Authoritative reading, ordered by prerequisite

- PDF: ISO 32000-1:2008 §7 (syntax/xref/object streams) and §12.6 (actions); PDF Association ISO 32000-2:2020 resource: https://pdfa.org/resource/iso-32000-2 .
- OOXML: ECMA-376 Part 2 Open Packaging Conventions: https://ecma-international.org/publications-and-standards/standards/ecma-376/ .
- OLE/CFB: Microsoft [MS-CFB] https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/53989ce4-7b05-4f8d-829b-d08d6148375b .
- VBA extraction: Microsoft [MS-OVBA] https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/575462ba-bf67-4190-9fac-c275523c75fc ; compression detail: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/4742b896-b32b-4eb0-8372-fbf01e3c65fd .
- YARA-X reference matcher/rules: https://github.com/VirusTotal/yara-x ; use to characterize parity, not as code claimed to be authored.

**Source honesty:** The design and risk estimates are recommendations inferred from inspected source, not benchmark measurements. Any new module remains proposed until implemented and tested.
