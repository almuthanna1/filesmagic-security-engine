# PDF attachment accuracy: pre-registration

Branch `feature/unified-pdf-accuracy`, from `341a972`. Baseline ("before"): the frozen release
`2d586f6` (tag `custom-engine-freeze-2026-11-09`), whose `app/` is identical to this branch's
starting point. Written and committed **before** the engine change and before any held-out sample
was scanned. Harness: [`evaluation/pdf_accuracy.py`](../evaluation/pdf_accuracy.py); hashes of the
private samples: [`evaluation/pdf_accuracy.json`](../evaluation/pdf_accuracy.json).

## 1. Problem (found on the development samples)

| | Document | Both engines | Cause, from the bytes |
|---|---|---|---|
| D1 | APA report, original export | SUSPICIOUS | A genuine attachment: a C2PA (Content Credentials) manifest, added by an incremental update (catalog rewritten as generation 1), linked from the catalog's `/AF` (`/AFRelationship /C2PA_Manifest`) and `/EmbeddedFiles`. Its `c2pa.icon` assertion holds an SVG image (`image/svg+xml`). The unified engine reports it as `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` (LOW): it verifies only OpenDocument packages. |
| D2 | D1 with embedded metadata removed | SUSPICIOUS | No attachment anywhere. The catalog keeps `/AF null` and an **empty** name tree, `/Names<</EmbeddedFiles<</Names[]>>>>`. The reference YARA-X rule `PDF_Embedded_File` (`$embedded = "/EmbeddedFile"`, LOW) matches the first 13 bytes of the key `/EmbeddedFiles`. The PDF scanner finds no attachment; the unified engine's attachment inspection finds none either, so it emits nothing that accounts for the YARA-X match, and the LOW stands. |
| D3 | D2 with those 44 marker bytes replaced by spaces (same length, every offset unchanged) | SAFE | Control: no marker, no attachment. |

So the D2 warning is a raw-byte signature reporting a dictionary key as an attachment. The D1
warning is a correct conservative result: an attachment exists, and its content type (C2PA/JUMBF
with an embedded SVG, which can carry script) is not one the engine can verify.

## 2. The change (one, narrowly scoped)

1. **`ENGINE_PDF_NO_ATTACHMENTS` (INFO, pdf-chains)** accounts for `yara-x:PDF_Embedded_File` only,
   and may lower it (SUPERSEDING ceiling LOW). It is emitted only when every one of these holds:
   - the attachment inspection is complete: every object of the cross-reference table (all
     generations) and every object-stream object was read, every raw object header is one the table
     points to, every raw `/EmbeddedFile` byte sequence lies inside a parsed object, no repair;
   - no file specification with `/EF` and no `/Type /EmbeddedFile` stream exists in any of them;
   - **every** raw `/EmbeddedFile` occurrence is the start of the name `/EmbeddedFiles` followed by a
     delimiter, and, object by object, the number of such occurrences equals the number of parsed
     `/EmbeddedFiles` keys whose value (direct or by reference) is an empty name tree: a dictionary
     with no `/Kids` and no or an empty `/Names` array;
   - in correlation: the chain scanner completed with no repair, and the reference PDF scanner
     completed without `PDF_EMBEDDED_FILE`, `PDF_EMBEDDED_EXECUTABLE` or `PDF_STRUCTURE_REPAIRED`.

   Its evidence lists each occurrence (byte offset, object, "empty name tree"). It never accounts
   for the PDF scanner's findings. Any doubt (text that merely contains the bytes, a non-empty or
   dangling tree, an older revision, bytes outside the parsed objects, repair) leaves the YARA-X
   finding as it is.
2. **Raw findings preserved:** every reference finding the correlation removes (by any rule, old or
   new) is appended to the evidence of that scanner's `ENGINE_CORRELATION` finding as
   `raw <scanner>:<rule> <SEVERITY>: <description>`, so the audit trail keeps its severity and text.

Not changed: every YARA-X rule (reference and engine), the reference scanners, the attachment
verifier (still only OpenDocument packages), every other correlation rule. C2PA manifests stay
unverified (LOW): a manifest can embed an SVG, and nothing is trusted by name, MIME type or
`/AFRelationship`.

## 3. Samples and labels

Labels are fixed by how a sample was made or obtained, never by a verdict.

| Split | Samples | Label | Use |
|---|---|---|---|
| dev | D1-D3 (private; hashes only) | benign (my own document and two derivations) | designing the change |
| dev | S01-S17, synthetic (`synthetic()`) | by construction: `no-attachment` (4), `attachment` (5), `ambiguous` (5), `dangerous` (3) | designing and testing the change |
| heldout | L01-L55 (private; hashes only): 28 PDF, 27 PPTX | benign by provenance: third-party course and career-office material | **not scanned before this commit**; never used to tune the change |
| heldout | `benign_corpus/independent` (IRS f1040, fw4, fw9; Census XLSX) | benign by provenance | not used to design this change; their earlier results are published in `docs/evidence/final-eda2a08-run3` |
| regression | `benign_corpus/files` (29) | known-benign (authored) | results known from earlier work: regression only, not held out |
| regression | `evaluation.cases` `cases()` (16), `field_cases()` (6) | inert synthetic, with indicators | must be identical before and after |

L01-L55 were chosen by a file-name rule before any scan: numbered lecture decks (`NN - Title`)
and named third-party handouts, articles and flyers; excluded were personal, financial and legal
documents, homework, exams and assignments, my own project documents, files of unknown origin and
duplicates (same SHA-256 counted once). Their names stay private.

Required outcomes for the synthetic samples: `no-attachment` SAFE; `attachment` and `ambiguous`
at least SUSPICIOUS (SAFE would be a missed attachment / a failure to fail safe); `dangerous`
MALICIOUS. For real benign documents: SAFE is correct, SUSPICIOUS is an **unexpected warning**
(reviewed case by case; not automatically a false positive), MALICIOUS is a **classification
error** (false positive), UNABLE_TO_SCAN is counted apart.

Genuine malware: not re-run. The recorded Emotet evaluation (VM only, frozen evidence) stands; the
change only affects PDFs (the chain scanner is not applicable to anything else). Nothing is
uploaded to Vercel, Render or production.

## 4. Metrics

Per split and per run (before/after x reference/unified): confusion matrix (label x verdict);
false-positive rate (MALICIOUS on benign) and any-warning rate (SUSPICIOUS or MALICIOUS on benign),
each with a 95% Wilson interval; per-rule contributions on benign documents (documents with the
rule, and documents where it is the only non-INFO finding); every verdict or non-INFO-rule change
between before and after; HIGH/CRITICAL findings lost; determinism over the trials; latency (wall
time per scan, each scanner's own time). False-negative *rates* are not computed: three dangerous
synthetic samples do not support a rate; counts are reported.

## 5. Predictions (falsifiable)

- **P1** Reference engine: identical verdicts and non-INFO findings on every sample.
- **P2** Unified: every change is SUSPICIOUS -> SAFE on a PDF whose only non-INFO finding before was
  `yara-x:PDF_Embedded_File` (LOW), with `ENGINE_PDF_NO_ATTACHMENTS` after. No other verdict changes.
- **P3** D1 stays SUSPICIOUS (`ENGINE_PDF_ATTACHMENTS_UNVERIFIED`); D2 SUSPICIOUS -> SAFE; D3 SAFE.
- **P4** Synthetic: S01-S03 SUSPICIOUS -> SAFE, S04 SAFE; S05-S14 unchanged and at least SUSPICIOUS;
  S15-S17 MALICIOUS before and after (S17 keeps its HIGH findings; its YARA-X LOW may be lowered).
- **P5** `cases()` and `field_cases()`: identical verdicts and non-INFO findings.
- **P6** No HIGH/CRITICAL finding lost anywhere; no new MALICIOUS on a benign document.
- **P7** Latency: unified median wall time per PDF scan changes by less than 10 ms (the inspection
  already reads every object; the new work is per marker occurrence).

## 6. Decision rules

A violation of P1, P4, P5 or P6 rejects the change: report it and stop. An unexpected held-out
result is reported as found; the code is not adjusted to it (a later fix would need a new held-out
set). Severity is lowered only by the rule above. Nothing is deployed; the staging Unified Engine
is updated only after explicit approval.
