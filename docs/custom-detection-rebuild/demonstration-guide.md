# Capstone demonstration guide

This guide is for presenting the Unified Security Engine to Dr. Haque. Every function and file
named here exists at commit `26ac5da`. `capstone-technical-guide.md` gives the full detail; this
guide is the presentation path. Run everything from the Security Engine root.

```
python -m evaluation.demo            # the three demonstrations below
python -m evaluation.demo pdf        # or one of them: pdf | vba | word
python -m evaluation.demo --save out # also write the inert files, to open them in a viewer
```

`evaluation/demo.py` runs the production roster in-process, in the same steps `POST /scan` takes in
its isolated worker: `app.worker.analyse` → `app.engine.correlate.correlate` →
`app.decision.decide` → `app.decision.classify`. `tests/test_demo.py` pins every verdict below, so
the demonstration cannot silently drift from the code.

## 1. The pipeline in one minute

```
upload ─► Conversion Engine (app/security_gate.py: check)
            │  Ed25519 token {aud, iat, exp=+120 s, jti, sha256, size}  ── POST /scan?engine=unified
            ▼
          Security Engine (app/main.py: scan_file)
            auth.verify ─► sha256/size must match the token ─► worker in Linux namespaces, no network,
            CPU/memory/file limits ─► 9 scanners ─► correlate ─► decide ─► classify
            │  signed receipt {verdict, authorization, commit, scanners, isolation_verified, …}, 300 s
            ▼
          Conversion Engine: verify_receipt ─► allow: convert │ consent_required: 409 + handle │ deny: 422
```

The roster, in `app/engine/__init__.py:16`, is `signatures`, `office`, `pdf`, `custom`, `pdf-chains`,
`pdf-integrity`, `vba-chains`, `ooxml-links` and `word-fields`. Every one is this repository's
code. The libraries only parse: pypdf, olefile, and oletools' VBA source extractor.

## 2. The parts, briefly

**Signature matcher** (`app/engine/signatures.py`). `Rule`s are written in Python
(`signature_rules.py`), with `literal()`/`regex()` patterns. `find_all` records at most 1000 matches
per pattern, a regex match is at most 4095 bytes, and a whole scan has a 10 s deadline. The
semantics are YARA's: `nocase` is ASCII folding, `wide` is UTF-16LE, `within(name, lo, hi)` is
`$x in (lo..hi)`. `tests/test_signatures.py` compares the matcher with YARA-X itself, as an oracle
in development only. The production image has no YARA-X.

**VBA tokenizer and deobfuscation** (`app/engine/vba_analysis.py`).
- `logical_lines` joins ` _` continuations.
- `tokenize` produces identifiers, strings (`""` is one quote), numbers (`&H`, `&O`) and operators,
  and drops comments.
- `statements` splits at `:` and at a one-line `If … Then`.
- `Fold` is a recursive-descent evaluator for constant expressions only: `&`/`+`, `Chr`,
  `StrReverse`, `Replace`, `Mid`, `Xor`, `Const` values, and so on. Anything it does not know stops
  the fold, and it never guesses.
- `Analyser` tracks object kinds from `CreateObject`/`GetObject` (`creation`, `chain_kind`) and
  decides each method by its receiver (`method`).

**VBA call graph** (`app/engine/vba_chains.py`).
- `parse` cuts modules into `Procedure`s.
- `link` adds call edges, each DEMONSTRATED or POSSIBLE. A procedure name can be shadowed by a
  parameter or a module variable.
- `search` runs two breadth-first searches from each automatic entry. The first follows
  demonstrated calls only, to a demonstrated capability, and gives LINKED. The second follows
  every edge and gives UNDETERMINED if anything dangerous or dynamic is reachable, otherwise NO_PATH.

**PDF action chains** (`app/engine/pdf_chains.py`). `extract` walks `/OpenAction`, `/AA` triggers,
`/A`, `/Next` and document-level `/JavaScript`. `_actions` caps the walk at 10 000 actions. Each
`Chain` says whether its trigger is automatic. `correlate.chain_findings` and `attachment_findings`
then link a script that calls `exportDataObject` to the embedded file it names, using
`pdf_attachments` to verify attachments.

**Office relationships and Word fields.**
- `app/engine/ooxml_links.py`: `analyse` follows the package's relationships part by part
  (`loaded_parts`, `_chain`). `classify` decides how each reference activates: on open, as an image,
  on click, and so on.
- `app/engine/word_fields.py`: `fields` rebuilds simple and complex fields from the XML;
  nested fields are an unknown `NESTED` placeholder. `tokens` splits the instruction, and
  `classify` maps DDE, DDEAUTO, INCLUDETEXT and INCLUDEPICTURE to rules. `is_program` decides
  whether a DDE application names a program.

**Findings to verdict.**
- `correlate.correlate` merges the structural findings with the engine's own. A reference finding is
  replaced only through an explicit `accounts for scanner:rule` link, and a macro execution finding
  is never removed.
- `decide` (`app/decision/__init__.py:17`):

  | Condition | Verdict |
  |---|---|
  | any HIGH or CRITICAL finding | MALICIOUS |
  | else any LOW or MEDIUM finding | SUSPICIOUS |
  | else no applicable scanner, a failed scanner, or incomplete coverage | UNABLE_TO_SCAN |
  | otherwise | SAFE |

- `classify` adds reasons and an authorization: `allow`, `consent_required` or `deny`.
  Only document reasons (a damaged or encrypted file) can be overridden with consent.
  Operational reasons (timeout, crash, unverified isolation) never get a receipt.

**How the engines trust each other.**
- The Conversion Engine signs a single-use token bound to the file's SHA-256 and size
  (`mint_token`).
- The Security Engine signs a receipt, and `verify_receipt` checks, in order:
  1. the signature and key;
  2. type and lifetime;
  3. the same file and the same request;
  4. the engine, `unified`;
  5. **the commit and the exact 9-scanner roster** (`accepted_releases`);
  6. `isolation_verified`;
  7. that the authorization is consistent with the verdict.
- A consent handle is single-use and bound to the same bytes.
- The browser never sees a receipt, so nothing the client sends can authorize a conversion.

## 3. Demonstration 1: a PDF action chain

Files: `auto-js-unrelated-attachment.pdf` (case `5a`) and `auto-js-exports-attachment.pdf` (case `5b`).
The two PDFs are the same shape: an `/OpenAction` that runs JavaScript, and one attachment.

| | 5a: script does not use the attachment | 5b: script exports it |
|---|---|---|
| Chain | `catalog /OpenAction: JavaScript (object 7 0)` | `catalog /OpenAction: JavaScript (object 7 0) (exports 'f')` |
| Findings | MEDIUM `pdf-chains:ENGINE_PDF_AUTO_CHAIN_SCRIPT`, MEDIUM `pdf:PDF_JAVASCRIPT`, LOW `ENGINE_PDF_ATTACHMENTS_UNVERIFIED` | **HIGH `pdf-chains:ENGINE_PDF_AUTO_CHAIN_DELIVERS_ATTACHMENT`**, plus the same two |
| Verdict | SUSPICIOUS, `consent_required` | MALICIOUS, `deny` |

Point to make: a keyword scanner sees "JavaScript" and "EmbeddedFile" in both files. The chain
analysis is what separates them: an automatic trigger → script → a data-object call naming this
attachment (`DATA_OBJECT_CALL` in `pdf_chains.py`). The attachment line `accounts for
pdf:PDF_EMBEDDED_FILE` shows the correlation replacing the generic finding with a more specific one.

In FilesMagic: 5a gives the consent dialog, and 5b is blocked with no continue button (staging,
§4.4 of the readiness report).

## 4. Demonstration 2: an inert VBA call path

Files: `v04-benign-formatting.docm`, `v01-autoopen-calls-shell.docm` and `v09-strreverse-progid-run.docm`.
Every command is the string `placeholder`, and nothing is ever executed.

- **v04.** A macro with no dangerous operation.
  - Findings: MEDIUM `OOXML_VBA_Macros`, LOW `OFFICE_MACROS_PRESENT`, and package findings.
  - Verdict: SUSPICIOUS. A macro document is never SAFE.
- **v01.** `AutoOpen` calls `Tool`, and `Tool` calls `Shell "placeholder"`.
  - `search` finds the demonstrated path `Module1.AutoOpen -> Module1.Tool (execute: Shell starts
    a program (line 5, command 'placeholder'))`.
  - Findings: HIGH `vba-chains:ENGINE_VBA_AUTOEXEC_REACHES_CAPABILITY` and HIGH
    `office:OFFICE_MACRO_AUTOEXEC_EXECUTION`.
  - Verdict: MALICIOUS.
- **v09.** The ProgID is hidden as `StrReverse("llehS.tpircSW")`.
  - `Fold` evaluates it to `WScript.Shell`, so `creation` gives the object kind and `method`
    resolves `.Run` on it: `execute: WScript.Shell.Run …`.
  - Verdict: MALICIOUS.

To show what the analysis will not claim, use the counterfactuals in
`phase8-production-readiness.md` §5. `Application.Run "Helper"` starts a macro, which is not an
execution (SUSPICIOUS). Make `Helper` call `Shell`, and the path becomes LINKED (MALICIOUS).

## 5. Demonstration 3: an external relationship and a dangerous Word field

Files: `hyperlink.docx`, `external-template.docx` and `ddeauto-field.docx`.

- **hyperlink.docx.** An external hyperlink activates only on a click, so it is not reported.
  Verdict: SAFE, `allow`.
- **external-template.docx.** The relationship chain is `package -> word/document.xml ->
  word/settings.xml -> attachedTemplate rId1 -> https://template.example.invalid/normal.dotm`.
  - Word fetches the template when the document opens.
  - Finding: MEDIUM `ooxml-links:ENGINE_OFFICE_EXTERNAL_ON_OPEN`.
  - Verdict: SUSPICIOUS. A remote template is a known delivery technique, but legitimate documents
    use it too, so the user decides.
- **ddeauto-field.docx.** The field `DDEAUTO c:\windows\system32\cmd.exe "/c placeholder"`.
  - `word_fields.classify` sees the DDEAUTO type, and `is_program` recognises `cmd.exe`.
  - Findings: HIGH `word-fields:ENGINE_WORD_DDEAUTO_PROGRAM` and HIGH `office:OFFICE_DDEAUTO_FIELD`.
  - Verdict: MALICIOUS, `deny`.

## 6. How FilesMagic acts on the verdict

| Verdict / authorization | Conversion Engine | What the user sees |
|---|---|---|
| SAFE / allow | converts, `X-FilesMagic-Security: SAFE` | "Conversion Complete!", Download |
| SUSPICIOUS or eligible UNABLE_TO_SCAN / consent_required | 409 + single-use handle; on resubmission converts, `ACKNOWLEDGED` | evidence, "Don't convert" / "I understand the risk, continue"; afterwards "Converted after you chose to continue…" |
| MALICIOUS or non-eligible UNABLE_TO_SCAN / deny | 422 `SCAN_BLOCKED` | "Malicious content detected", only "Choose a different file" |
| no valid receipt (engine down, timeout, commit or roster mismatch) | 503 `SCAN_UNAVAILABLE` | try again later; nothing is converted |

## 7. Questions Dr. Haque is likely to ask

**Why write your own matcher instead of using YARA-X?** The goal was detection logic this project
can explain and own. The matcher keeps the YARA semantics the rules relied on, and it is tested
against YARA-X as an oracle, so the replacement is measured rather than assumed. YARA-X is not in
the production image.

**Does anything ever execute the macro or the JavaScript?** No. Everything is static: tokens, folded
constants and graphs. The scan also runs in a worker with no network, separate namespaces and
resource limits, so a parser exploit has little to reach.

**Why did five VBA cases drop from MALICIOUS to SUSPICIOUS? Isn't that weaker?** Each was a
keyword match without the capability: a `vbHide` constant, `Application.Run` of a macro, a harmless
shell32 API, a user procedure named `Shell`, `Run` on an unknown object. For each I built the
attacker's nearest variant, and every one is still MALICIOUS. That test found one real gap (an
object passed as a parameter), which commit `04a3c7c` closes. A macro file is still never SAFE.

**What if the VBA source is benign but the P-code is malicious (stomping)?** It cannot be detected
from source. That is why correlation never lowers `OFFICE_MACRO_AUTOEXEC_EXECUTION` on a "no path"
result. It is a documented limitation.

**Can the frontend bypass the block?** No. The frontend never holds a receipt. Forged consent
handles, `verdict=SAFE` form fields, fake receipts and a spoofed `X-FilesMagic-Security` header were
all tried on staging, and every one got 422.

**What happens if the Security Engine is down or slow?** The gate fails closed with 503, and nothing
is converted. On staging an unreachable engine answered in 2 s, and a hanging one at the 60 s
timeout.

**How do you deploy a new engine without an outage, when the gate pins one commit?** The gate can
trust a second commit, `SECURITY_ENGINE_PREVIOUS_COMMIT`, each bound to its own roster. The
Conversion Engine is deployed first, trusting both; then the Security Engine; then the old commit
is removed. This was rehearsed on staging against the real old engine.

**What does SAFE mean?** No known indicator was found, and every applicable scanner completed with
full coverage. It does not mean the file is proven harmless; the UI says exactly that.

**What are the false-positive risks?** Legitimate macros that really call `Shell` on open, PDF forms
with automatic JavaScript, and remote templates. The first are blocked; the others ask for consent.
The fail-closed `Run`/`Exec` rule can block a macro that also uses an unrelated `.Run`.

**How was it validated?**
- 1314 tests on Linux CI, with the isolation tests required.
- Regression against the previous engine (`regression-report.md`).
- 33 known-benign files.
- 32 + 6 + 5 end-to-end checks on staging.
- A browser run of the real frontend.

No real malware was used, so no detection rate is claimed.

## 8. What to study first

1. `app/decision/__init__.py` (`decide`, `classify`). It is short, and every other answer leads here.
2. `app/engine/vba_chains.py:257` (`search`): the two breadth-first searches.
3. `app/engine/correlate.py:399` (`correlate`) and the `accounts for` mechanism.
4. The Conversion Engine's `app/security_gate.py`: `verify_receipt` and `accepted_releases`.
5. Run `python -m evaluation.demo` once and read each evidence line against the code above.
