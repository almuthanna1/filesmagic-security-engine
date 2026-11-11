# C2PA Content Credentials accuracy: pre-registration

Branch `feature/unified-c2pa-accuracy`, from `6739cb4`, whose `app/` is that of `9882cbf` (the
accepted PDF accuracy change, live on staging). Baseline ("before"): `9882cbf`. Written and
committed **before** the engine change and before any held-out file was opened or scanned. Public
corpus: [`evaluation/c2pa_corpus.json`](../evaluation/c2pa_corpus.json) (URL at a pinned commit,
licence, size, SHA-256, UTC acquisition time; the files are not redistributed). Harness, to be
written: `evaluation/c2pa_accuracy.py`, reusing [`evaluation/pdf_accuracy.py`](../evaluation/pdf_accuracy.py).

## 1. Problem (found on the development samples)

| | Sample | Both engines | Cause, from the bytes |
|---|---|---|---|
| D1 | APA report (private), exported from ChatGPT | SUSPICIOUS | Its one attachment, "Content Credentials", is a C2PA manifest store (claim generator `ChatGPT`, spec 2.2.0): one manifest with a claim and a claim signature (CBOR, COSE_Sign1) and three assertions: `c2pa.icon`, an embedded SVG of 2,415 bytes (elements `svg`, `path`; attributes `d`, `fill`, `height`, `viewBox`, `width`), `c2pa.actions.v2` and `c2pa.hash.data` (CBOR). Reference: `PDF_EMBEDDED_FILE` LOW, `PDF_Embedded_File` LOW. Unified: `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` LOW, "not an OpenDocument package": the verifier knows no other type. The catalog's rewrite is generation 1, so the inspection is complete. |
| CD04-CD08 | 5 public manifests (test files of the CAI's c2pa-rs library) | n/a (not PDFs) | Content boxes `cbor`, `json`, `bfdb`+`bidb` (JPEG thumbnails of 26-50 KB, one PNG of 7 KB); description toggles `0x03` and `0x13` (a private `c2sh` salt box, 16 bytes); superbox nesting at most 4; no `XLBox`; no markup or control character in any of the 56-366 text strings per store. |
| CD01 | `basic-signed.pdf` (c2pa-rs) | n/a | No C2PA: an Acrobat Sign signature on an encrypted PDF. Used as a control. |

So every C2PA attachment is reported, whatever it holds. Nothing in D1's manifest can run: its
only non-data item is a static vector icon. The C2PA specification (2.2, Annex A.4) embeds the
manifest store as an embedded file stream (`/Subtype application/c2pa`,
`/AFRelationship /C2PA_Manifest`), linked from the catalog's `/AF` and from `/EmbeddedFiles` or a
file attachment annotation; with incremental updates one PDF can hold several manifest stores.

## 2. The change (one, narrowly scoped)

The attachment verifier (`app/engine/pdf_attachments.py`) gains a second verifiable type, **a C2PA
manifest store without active content** (new module `app/engine/c2pa.py`). Unchanged: every rule
and severity, `ENGINE_PDF_ATTACHMENTS_VERIFIED` (INFO; SUPERSEDING ceiling LOW, for
`PDF_EMBEDDED_FILE` and `PDF_Embedded_File` only), the completeness and action conditions, every
other correlation rule, every YARA-X rule, the reference engine.

An attachment is verified as one only if **all** of the following hold. They are decided from its
decoded bytes, never from `/Subtype`, `/AFRelationship`, its name, a signature or a claim generator:

1. **Bounds.** The decoded bytes count against the PDF's shared read budget (16 MiB); at most
   10,000 boxes; superbox nesting at most 8; at most 100,000 CBOR data items per store, nested at
   most 64 deep; at most 10,000 SVG elements. Nothing is inflated beyond the PDF stream filters
   (already bounded by `PDF_LIMITS`): Brotli-compressed manifests (`brob`), PNG and JPEG data and
   gzip-compressed SVG are never decompressed. Every check is linear in the bytes and capped by
   these counts, so processing time is bounded deterministically and a verdict never depends on
   the machine's speed; the worker's 30 s wall-clock timeout stays. The worst case is measured.
2. **JUMBF (ISO/IEC 19566-5).** The bytes are exactly one superbox (`jumb`) from the first byte to
   the last: every length consistent (`LBox` at least 8, `XLBox` allowed, `LBox` 0 rejected), every
   box inside its parent, nothing trailing. Its description box carries the C2PA manifest store
   UUID `63327061-0011-0010-8000-00AA00389B71` and the label `c2pa`. Every superbox begins with
   exactly one description box (`jumd`): a 16-byte UUID, toggles with the reserved bits clear, a
   NUL-terminated UTF-8 label, a 4-byte ID, a 32-byte hash and a private box (only `c2sh`, 16 or 32
   bytes of salt), each present only if its toggle says so, and nothing else.
3. **Content boxes**, classified by box type and bytes:
   - `cbor`: exactly one well-formed CBOR data item (RFC 8949) filling the box: valid argument
     encodings, every length inside the box, text strings valid UTF-8, indefinite lengths properly
     terminated, no reserved encodings, no repeated key in a map. Byte strings (hashes, signatures,
     certificates, salts) are opaque data and are not rendered by any consumer.
   - `json`: UTF-8 JSON, no NaN or Infinity, no repeated key.
   - `bfdb` immediately followed by `bidb` (an embedded file): `bfdb` toggles 0 or 1 (a file name
     may follow the media type; any other bit, such as an external reference, is not verified). The
     `bidb` bytes must be, by their own structure: **JPEG** (SOI, every segment inside, entropy-coded
     data correctly stuffed, EOI as the last two bytes), **PNG** (signature, chunks with valid
     CRC-32, `IHDR` first, `IEND` last, nothing after) or a **static SVG** (point 4). The declared
     media type must name the format found.
   - `free` (padding): zero bytes only.
   - Anything else is not verified: `uuid` (custom or encrypted data), `brob`, `xml`, `jp2c`,
     protection boxes, `bidb` without `bfdb`, unknown types.
4. **Static SVG.** Parsed with defusedxml (no DTD or entities, nothing fetched); no processing
   instruction; every element in the SVG namespace and one of `svg g defs title desc path rect
   circle ellipse line polyline polygon linearGradient radialGradient stop clipPath mask`; every
   attribute without a namespace and on a fixed list of geometry and presentation attributes; no
   attribute value with a backslash, a colon or a `url()` other than `url(#id)`. So: no script,
   event handler, style sheet, `foreignObject`, `image`, `use`, link, animation, filter or external
   reference.
5. **Text** (CBOR text strings and map keys, JSON strings and keys, `jumd` labels, `bfdb` names,
   SVG text and attribute values): no control or formatting character other than tab, line feed
   and carriage return (no NUL, backspace, bidirectional override or zero-width character); no
   markup a renderer could act on: `<` followed by a letter, `/`, `!` or `?`; an event-handler
   attribute (`on<letters>=`); a `javascript:` or `vbscript:` URL.
6. **Pictures** (JPEG, PNG): their raw bytes contain no active HTML or SVG markup (`<script`,
   `<html`, `<svg`, `<iframe`, `<object`, `<embed`, `<body`, `<meta`, `<link`, `<style`, `<form`,
   `<base`, `<foreignObject`, an event-handler attribute, a `javascript:` or `vbscript:` URL): a
   polyglot check.
7. **Name.** Every name of the file specification has no control or formatting character and
   either no `.` at all or the extension `.c2pa`: a reader saves the attachment under that name,
   and the system opens it by extension.

The PDF-level conditions for `ENGINE_PDF_ATTACHMENTS_VERIFIED` are unchanged and still required:
every attachment in every object is verified (OpenDocument or C2PA); the attachment list is
complete (an older revision, bytes outside the parsed objects or a repair give
`ENGINE_PDF_ATTACHMENTS_INCOMPLETE` and nothing is lowered); no action anywhere runs a script,
launches a file or opens an embedded document. A chain that can deliver the attachment keeps its
own finding (`ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT`, HIGH, and so on), so the presence of a
manifest is never confused with a way to activate it.

Evidence: each verified store lists its manifests, assertion labels and picture types and says
"signature not validated"; a store not verified names the first item that failed and why (for
example "assertion c2pa.icon: SVG element script"). Removed reference findings stay, as they were,
in `ENGINE_CORRELATION` (`raw ...` lines).

Out of scope, stated in the evidence where it matters: signature and certificate validation, the
hash binding (`c2pa.hash.data`), trust lists, ingredient resolution, reading older revisions,
Brotli, decoding pictures beyond their structure. "Verified" means "no active content in a
structure read completely", never "authentic" or "trusted".

## 3. Samples and labels

Labels are fixed by how a sample was made or obtained, never by a verdict.

| Split | Samples | Label | Use |
|---|---|---|---|
| dev | D1 (private; hash in `pdf_accuracy.json`) | benign | designing the change |
| dev | CD04-CD08, each embedded into a minimal PDF exactly as D1 links its manifest ("derived") | `c2pa-benign` by provenance (c2pa-rs test files) | designing |
| dev | CD01-CD03 (c2pa-rs PDFs without C2PA) | benign | controls |
| dev | synthetic cases (section 4) | by construction | designing and testing |
| dev | CA01-CA05 (c2pa-attacks strings), each line injected into a synthetic benign manifest's claim title | `attack-string` | evaluation (outcomes predicted in P8) |
| heldout | CH01 (the official PDF test file), CH02 (`express-signed.pdf`, c2pa-rs) | benign by provenance | **not opened before this commit** |
| heldout | CH03-CH07 (c2pa-rs PDFs) | benign | controls, not opened |
| heldout | CH08-CH31: the manifests of 24 official JPEG test files (Adobe: 20, including the error cases; Nikon: 1; Truepic: 3), derived as above | `c2pa-benign` by provenance | not opened |
| regression | the previous study's corpus (`pdf_accuracy.samples()`: D2, D3, L01-L55, IRS/Census, `benign_corpus/files`, S01-S17, `cases()`, `field_cases()`) | as there | identical results expected |

Derived PDFs: a one-page PDF whose catalog has `/AF [5 0 R]` and
`/Names << /EmbeddedFiles << /Names [(Content Credentials) 5 0 R] >> >>`, with D1's dictionaries
byte for byte: object 5 `<< /AFRelationship /C2PA_Manifest /Desc (Content Credentials) /F (Content
Credentials) /EF << /F 6 0 R >> /Subtype (application/c2pa) /Type /Filespec /UF (Content
Credentials) >>`, object 6 the uncompressed stream `<< /Type /EmbeddedFile /Subtype
/application#2Fc2pa >>`. A JPEG's manifest is its APP11 JUMBF packets reassembled (C2PA 2.2,
Annex A.3). The error cases (invalid
signature, hash mismatch, missing claim) are benign: their faults are in provenance, not content.

Required outcomes: `c2pa-benign` (derived and synthetic) SAFE; `c2pa-active`, `c2pa-deceptive` and
`c2pa-malformed` at least SUSPICIOUS (SAFE is a **false negative**); `dangerous` MALICIOUS. Real
benign documents: SAFE correct, SUSPICIOUS an **unexpected warning** (reviewed case by case),
MALICIOUS a **classification error** (false positive), UNABLE_TO_SCAN counted apart.

No genuine malware is used or uploaded; the attack strings are text. Nothing is uploaded to
Vercel, Render or production.

## 4. Synthetic cases (inert; built in code)

- `c2pa-benign`: CBOR-only manifest; with a JPEG thumbnail; with a PNG thumbnail; with a static SVG
  icon (D1's shape); with a JSON assertion; with salt and padding boxes; named `manifest.c2pa`; two
  manifest stores; a manifest next to a verified OpenDocument attachment.
- `c2pa-active`: an SVG icon with a `script` element; an `onload` attribute; `foreignObject` with
  HTML; an `a` with a `javascript:` link; an `image` with an external link; a `style` element;
  an `xml-stylesheet` instruction; a DTD with an entity; `use` of an external document; `set`
  changing an `href`; a `url(https://...)` fill; an HTML document in `bidb`; an XSS string in the
  claim; a right-to-left override in a label.
- `c2pa-deceptive`: `MZ` bytes declared `image/jpeg`; a JPEG thumbnail with HTML after EOI; a
  JPEG with `<script>` in a comment segment; a PNG with a ZIP after `IEND`; `image/png` holding a
  JPEG; a `bfdb` external reference; `MZ` bytes under `/AFRelationship /C2PA_Manifest` named
  "Content Credentials"; a valid store named `Content Credentials.html`; a `uuid` content box; a
  `brob` (compressed) manifest; a first superbox that is not the manifest store.
- `c2pa-malformed`: truncated; trailing bytes; a box longer than its parent; nesting beyond the
  limit; more boxes than the limit; CBOR with trailing bytes, invalid UTF-8, a repeated key, an
  unterminated indefinite array; JSON with a repeated key; a PNG CRC mismatch; a JPEG without EOI.
- Activation: an otherwise verifiable manifest with `/OpenAction` JavaScript `exportDataObject` of
  it (`dangerous`); with `/OpenAction /Launch` of it (`dangerous`); with a link that runs
  JavaScript (`c2pa-active`: at least SUSPICIOUS); next to a text attachment (at least SUSPICIOUS);
  added by an incremental update that rewrites the catalog under the same number and generation
  (at least SUSPICIOUS: an older revision makes the list incomplete, the known limit of this change).

## 5. Metrics

Per split and per run (before/after x reference/unified): confusion matrix (label x verdict);
false positives and any-warning rate on benign samples with 95% Wilson intervals; false
negatives (count, with each case); per-rule contributions; every verdict or non-INFO-rule change
with the reason; HIGH/CRITICAL findings lost; determinism over 3 trials; latency (wall time per
scan; each scanner's time; the paired difference of `pdf-chains` per PDF; the worst case at the
limits of point 1). False-negative rates are not computed: the cases are constructed.

## 6. Predictions (falsifiable)

- **P1** Reference engine: identical verdicts and non-INFO findings on every sample.
- **P2** D1: SUSPICIOUS -> SAFE through `ENGINE_PDF_ATTACHMENTS_VERIFIED`, whose evidence names the
  manifest, its three assertions and the static SVG and says the signature was not validated; both
  reference LOW findings kept as raw evidence.
- **P3** Dev derived (CD04-CD08): SUSPICIOUS -> SAFE, 5 of 5.
- **P4** Held-out derived (CH08-CH31): each SAFE, or SUSPICIOUS with a reason naming content outside
  point 3; at least 20 of 24 SAFE; none MALICIOUS.
- **P5** Held-out PDFs: CH01 stays SUSPICIOUS, predicted cause an incremental update that rewrote
  an object under the same number and generation (`ENGINE_PDF_ATTACHMENTS_INCOMPLETE`). If its
  inspection is instead complete and its manifest meets section 2, SAFE. CH02: if it carries a C2PA
  manifest, the same reasoning; if not, unchanged. Neither MALICIOUS.
- **P6** Controls (CD01-CD03, CH03-CH07) and every regression sample: identical verdicts and
  non-INFO findings.
- **P7** Synthetic: `c2pa-benign` SUSPICIOUS -> SAFE; every `c2pa-active`, `c2pa-deceptive` and
  `c2pa-malformed` case at least SUSPICIOUS (0 false negatives), its reason naming the item; the two
  `dangerous` cases MALICIOUS.
- **P8** Attack strings: the 4 XSS strings and every string with a control character other than
  tab, line feed and carriage return are SUSPICIOUS; SQL-injection strings, the 10,000-character
  string and plain punctuation are SAFE. That is policy, stated here so it is not read as a miss:
  text without markup or control characters is shown as text by C2PA consumers and does nothing
  in the PDF; SQL injection targets services that store metadata, not the reader of this file.
- **P9** No HIGH/CRITICAL finding lost; no new MALICIOUS on a benign sample; every scan deterministic.
- **P10** Latency: on PDFs without a C2PA manifest, paired median change of `pdf-chains` under 1 ms;
  on C2PA PDFs, paired median increase under 20 ms; the worst case at the limits under 2 s.

## 7. Decision rules

A violation of P1, P6, P7 (any false negative) or P9 rejects the change: report it and stop.
Held-out results are reported as found; the code is not adjusted to them (a later fix would be
post hoc and need a new held-out set). Deviations from P2-P5, P8 or P10 are reported and
explained. Nothing is deployed; the staging Unified Engine is updated only after explicit
approval.
