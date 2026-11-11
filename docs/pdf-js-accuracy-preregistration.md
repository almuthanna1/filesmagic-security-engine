# PDF JavaScript accuracy (CD03): pre-registration

Branch `feature/unified-pdf-js-accuracy`, from `d456d99`, whose `app/` is that of `e2eb2c7` (the
accepted C2PA change, live on staging). Baseline ("before"): `d456d99`. Written and committed
**before** the engine change and before any held-out file was scanned or its scripts read (the
held-out files were only downloaded and hashed). Corpus: [`evaluation/js_corpus.json`](../evaluation/js_corpus.json)
(pinned commit, path, URL, size, SHA-256, UTC acquisition time; the files are not redistributed).
Harness, to be written: `evaluation/pdf_js_accuracy.py`, reusing `evaluation/pdf_accuracy.py` and
`evaluation/c2pa_accuracy.py`.

## 1. Problem (found on the development samples)

CD03 (c2pa-rs `sdk/tests/fixtures/basic-attachments.pdf`, SHA-256 `74731af2...567de78`, made with
Acrobat Pro 23.1) is MALICIOUS in both engines. Its only JavaScript is one document-level script,
named `ADBE::FileAttachmentsCompatibility` in the catalog's `/Names /JavaScript` tree (object 29,
in an object stream). A document-level script runs when the document opens in a viewer with
JavaScript enabled, so it is genuinely executable and automatically triggered, not a raw-byte
artefact. Read in full (1,385 characters), it does this:

    var v = app.viewerVersion;
    if (v < 7) {                                     // nothing at all on Acrobat/Reader 7 or later
      n = this.dataObjects.length (if any)
      Acrobat 5.x Full / Fill-In with attachments:   app.alert(message, 3, 0)
      Acrobat 6.x: if n == 0, for p = 0 .. numPages-1: annots = this.getAnnots(p),
                   n = 1 if one has type "FileAttachment"; then if n > 0: app.alert(message, 3, 0)
    }

APIs used: `app.viewerVersion`, `app.viewerVariation`, `this.dataObjects` (only `.length`),
`this.external`, `this.numPages`, `syncAnnotScan()`, `this.getAnnots(p)`, `app.alert`. No string
is evaluated, nothing is exported, opened, launched, submitted or fetched.

Why each engine says MALICIOUS:

- Reference: `PDF_JAVASCRIPT_EXPLOIT_API` (HIGH), because the regular expression `EXPLOIT_JS`
  (`app/scanners/pdf.py`) contains `\.getAnnots\s*\(` and matches `this.getAnnots(p)`; and
  `PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD` (HIGH): an automatic script plus any attachment (two PNGs).
- Unified: the second HIGH is already replaced by the action-chain rules (`ENGINE_PDF_AUTO_CHAIN_SCRIPT`,
  MEDIUM: the chain uses no attachment). `PDF_JAVASCRIPT_EXPLOIT_API` (HIGH) stands and alone makes it
  MALICIOUS.

`getAnnots` is on the list because of CVE-2009-1492: memory corruption in Reader/Acrobat 9.1,
8.1.4, 7.1.1 and earlier when an OpenAction script calls `getAnnots` with **crafted integer
arguments**. Here it receives a page index from 0 to `numPages - 1`, the documented use, and only
on Acrobat 6.x.

Development survey (both engines, `d456d99`, every `/JS` in every cross-reference object): of 176
dev PDFs (CD03 and Apache PDFBox's 175 test PDFs), 3 are MALICIOUS, all for this reason only:
CD03, PDFBox `pdfbox/src/test/resources/input/compression/attachment.pdf` (Word 2010 export,
`8f22a77c...`) and `tools/src/test/resources/org/apache/pdfbox/testPDFPackage.pdf` (Acrobat 8.1,
`9676f28b...`; Apache Tika ships the same bytes). Their scripts (SHA-256 of the text `e5e41afb...`,
`ac26d342...`, `736c6999...`) differ **only in the four `app.alert` message strings** (English,
German, and "Acrobat" for "Adobe Acrobat"); every other character is identical.

**Assessment (to be confirmed by the evaluation):** CD03 is a false positive as MALICIOUS: no
condition of the exploit holds. It is not a false positive as SUSPICIOUS: it does run JavaScript
automatically, which this engine reports as MEDIUM for every document (as for the IRS forms), so
the expected verdict is SUSPICIOUS, not SAFE.

## 2. The change (Unified Engine only; the reference engine is not touched)

A new module `app/engine/pdf_scripts.py` recognises a script by its whole code: a **reviewed
template**, the text of CD03's script with each of the four `app.alert` message literals replaced
by a slot. A script is recognised only if the template matches all of it (`fullmatch`): every
character outside the slots identical (no whitespace, line-ending or comment differences), and
each slot exactly one double-quoted JavaScript string literal on one line
(`"(?:[^"\\\r\n  ]|\\[^\r\n  ])*"`). A string literal is data: it cannot end
early, hold code or change control flow; the slots only change the text an alert shows on Acrobat
5 or 6. The comparison strings (`"Full"`, `"Fill-In"`, `"FileAttachment"`), numbers and every
call are fixed.

The action-chain scanner takes an inventory of scripts from a complete reading: every object in
the cross-reference table and object streams, with every dictionary nested in it (as the attachment
inspection does), each `/JS` read with the PDF scanner's `text_of` (the same text its `EXPLOIT_JS`
searched). Not recognised (fail closed), so nothing changes, when: any script does not match; more
than 100 scripts; a script longer than 16,384 characters; an `/XFA` form, a 3D `/OnInstantiate`
script or `/RichMediaContent` exists (scripts outside `/JS`); any script cannot be decoded.

If every script is recognised (at least one), it reports `ENGINE_PDF_SCRIPTS_RECOGNISED` (INFO),
listing each script, and accounts for `pdf:PDF_JAVASCRIPT_EXPLOIT_API`. Correlation removes that
HIGH finding only if, in addition: the PDF scanner and the chain scanner completed, the structure
needed no repair (`ENGINE_PDF_CHAINS_REPAIRED` absent), and the attachment inspection's complete
reading succeeded (no `ENGINE_PDF_ATTACHMENTS_INCOMPLETE`: every object header in the raw bytes is
one the table points to). `SUPERSEDING` gets one entry, this rule with ceiling HIGH: it may
replace a HIGH, never a CRITICAL, and only the finding it names. The removed finding stays in the
audit trail (`ENGINE_CORRELATION`, `raw pdf:PDF_JAVASCRIPT_EXPLOIT_API HIGH: ...`).

Everything else stays: `PDF_JAVASCRIPT` (MEDIUM), the chain rules (`ENGINE_PDF_AUTO_CHAIN_SCRIPT`
MEDIUM; any attachment rule), every other reference finding. Nothing about the script's trigger,
name (`ADBE::...` names are chosen by whoever writes the file) or producer is trusted.

What it does not do: decide anything about scripts other than the reviewed one; interpret
JavaScript; touch `util.printf`, `Collab.*`, `media.newPlayer`, `spell.customDictionaryOpen` or
`exportDataObject` matches (they stand, as before).

## 3. Samples and labels

- **dev**: CD03 (pinned in `evaluation/c2pa_corpus.json`) and the 172 unique Apache PDFBox test
  PDFs (`apache/pdfbox@599a1de`) in `js_corpus.json`; the synthetic cases (section 4). Used to
  design the change; the template was taken from CD03 and checked against the two PDFBox variants.
- **held-out**: the unique Apache Tika (`apache/tika@a40d54f`, 60) and Mozilla pdf.js
  (`mozilla/pdf.js@421ff37`, 1,091) test PDFs in `js_corpus.json`. Files identical to an earlier
  entry (SHA-256) are evaluated once, under that entry (dev before held-out); 27 duplicates.
- **regression**: every sample of the C2PA study (`evaluation.c2pa_accuracy.samples`: the previous
  studies' corpora, the private APA variants checked against committed hashes, the C2PA corpus and
  synthetic cases), except CD03, which is dev here.

Labels. The public test PDFs are library fixtures, not labelled by their authors. Label `fixture`;
reported per verdict, not as benign or malicious rates. After the run, each held-out file that is
MALICIOUS before or after, or whose verdict changes, is inspected and described (its scripts and
triggers), with the criterion fixed here: "dangerous" only with an exploit-shaped call (an API of
`EXPLOIT_JS` with oversized or crafted arguments, heap-spray or shellcode patterns, code built from
strings and evaluated) or an automatic payload (launch, export or open of an attachment);
otherwise "benign script". No genuine malware is acquired: dangerous JavaScript is reproduced in
inert synthetic form (section 4); real exploit samples would need the contained environment of
`docs/genuine-malware-evaluation-plan.md` and separate approval.

## 4. Synthetic cases (inert; built in code)

`js-benign` (expected SUSPICIOUS after, unified; MALICIOUS before):
- J01 the template with CD03's messages, document-level; J02 German messages; J03 messages with
  quotes, `\"` escapes, `'`, `//`, `/*`, `</script>`, `eval(` and `getAnnots(` as text; J04 the
  same script twice (two name-tree entries); J05 the script as an `/OpenAction` instead (location
  is not trusted, and does not matter to what the code does); J06 the script in a FlateDecode
  stream; J07 in an object stream; J08 a UTF-16BE text string; J09 with two PNG attachments (CD03's
  shape); J10 the template in a PDF encrypted with an empty user password (read after
  decryption, as both scanners do).

`js-dangerous` (expected MALICIOUS before and after, both engines):
- J20 `getAnnots` with crafted integers (`this.getAnnots(-1073741821, -1073741823, -1073741822, -1073741823)`);
  J21 `util.printf("%45000f", ...)`; J22 `Collab.collectEmailInfo({msg: <long string>})`; J23
  `Collab.getIcon(<long string>)`; J24 `media.newPlayer(null)`; J25 `spell.customDictionaryOpen(...)`;
  J26 `exportDataObject({cName: "a.exe", nLaunch: 2})` with the attachment; J27 heap-spray shape
  (`unescape("%u0c0c...")` in a loop) plus `getAnnots`.
- J30 the template plus one appended statement; J31 the template with `this.getAnnots(p)` changed to
  `this.getAnnots(-1, -1, -1, -1)`; J32 the template with one call added inside a slot position's
  argument list (`app.alert("x" + eval(...), 3, 0)`); J33 the template plus a second, dangerous
  script in an `/OpenAction`; J34 in a page `/AA /O`; J35 in a form field's `/AA`; J36 in an object
  reachable from nothing (only in the cross-reference table); J37 in an incremental update; J38 the
  template plus an XFA form; J39 the template plus a 3D `/OnInstantiate` stream; J40 the template
  with a dangerous script whose key is written with `#` escapes (`/J#53`, `/Java#53cript`).
- J50 the template with CRLF line endings (not recognised, fail closed: stays MALICIOUS); J51 the
  template with one extra space (the same); J52 a template script longer than 16,384 characters
  through a long message (the same).

`js-malformed` (expected unchanged; never SAFE): J60 the template in a PDF whose cross-reference
table is broken (repaired by the parser); J61 truncated after the script object; J62 an object
header outside the table (an older revision).

## 5. Metrics

Per split and run (before/after x reference/unified): verdict counts per label; every verdict or
non-INFO-rule change with the reason; HIGH/CRITICAL findings lost; determinism (3 trials on dev,
synthetic and every held-out PDF that has a `/JS`; 1 trial on the rest, which the change can only
affect through the inventory walk). Latency: paired difference of `pdf-chains` per PDF (median, 95th
percentile, maximum), split by PDFs with and without `/JS`; the worst constructed case (100
template scripts; 100 large non-matching scripts). Memory: peak working set of a fresh process
scanning each PDF with `/JS` (unified, in-process), before and after.

## 6. Predictions (falsifiable)

- **P1** Reference engine: identical verdicts and non-INFO findings on every sample.
- **P2** CD03, unified: MALICIOUS -> SUSPICIOUS; `PDF_JAVASCRIPT_EXPLOIT_API` removed through
  `ENGINE_PDF_SCRIPTS_RECOGNISED` and kept as a raw line; `PDF_JAVASCRIPT` (MEDIUM),
  `ENGINE_PDF_AUTO_CHAIN_SCRIPT` (MEDIUM), `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` (LOW) kept.
- **P3** The two PDFBox variants: the same, MALICIOUS -> SUSPICIOUS (their only HIGH is the same).
- **P4** Held-out: a verdict or non-INFO finding changes only where every script is recognised, and
  each such change is the removal of `PDF_JAVASCRIPT_EXPLOIT_API` (unified). Number of such files:
  not predicted (the held-out scripts were not read); reported as found.
- **P5** Held-out: no other change; no new finding on any file.
- **P6** Synthetic: every `js-benign` case SUSPICIOUS after (unified); every `js-dangerous` case
  MALICIOUS before and after in both engines, with `PDF_JAVASCRIPT_EXPLOIT_API` kept (J33-J40 also
  keep it, because not every script is recognised); `js-malformed` unchanged.
- **P7** Regression: identical verdicts and non-INFO findings on every sample (none carries the
  script).
- **P8** No HIGH/CRITICAL lost other than `PDF_JAVASCRIPT_EXPLOIT_API` on files whose every script
  is recognised; no new MALICIOUS; every scan deterministic.
- **P9** Latency: paired median `pdf-chains` change under 1 ms on PDFs without `/JS` and under 5 ms
  with `/JS`; worst constructed case under 1 s locally. Memory: median peak difference under
  1 MiB, maximum under 5 MiB.

## 7. Decision rules

A violation of P1, P5, P6, P7 or P8 rejects the change: report it and stop. Held-out results are
reported as found; the template is not adjusted to them (a new reviewed script would need its own
review and a new held-out set). Deviations from P2-P4 or P9 are reported and explained. Nothing is
deployed; staging is updated only after explicit approval.

## 8. Separate investigations (no detection change)

- The 15.5 s staging case (`limits-19`, `docs/evidence/c2pa-accuracy-e2eb2c7/staging-e2eb2c7.md`):
  profile which part of the C2PA verification takes the time, locally, and whether a bound on work
  (not on time) can keep the worst case well inside the worker's 30 s on the free instance. Any
  change is proposed separately, with its own measurements.
- Memory telemetry: how to obtain each scan's peak memory on staging without the Render dashboard
  (for example the worker's own `getrusage` maximum resident set, reported per scan in the log and
  the response). Proposed separately; it touches the shared worker, not detection.
