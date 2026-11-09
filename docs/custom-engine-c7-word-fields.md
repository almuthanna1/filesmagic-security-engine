# C7: Word field-code analysis

**FilesMagic Security Engine · NIU CSCI 499 Honors Capstone**

The custom engine's seventh component, planned in the
[research log](custom-engine-research-log.md) (Section 16.6) and approved on 2026-11-08 with a
narrow scope. "C7" is the custom-engine component number. It is not the Render staging phases
C7A-C7D of the [evidence package](capstone-evidence-package.md).

Code: [app/engine/word_fields.py](../app/engine/word_fields.py), scanner `word-fields` in the
unified engine only. Tests: [tests/test_word_fields.py](../tests/test_word_fields.py), with
inert packages built in memory: `.invalid` hosts, the command `rem inert`, and no file written.

## 1. What a field is, and why it matters

A Word field is an instruction stored in the document and evaluated by Word when the field is
updated: page numbers, tables of contents, mail-merge values. A few field types reach outside the
document:

| Field | What Word does when it updates it |
|---|---|
| `DDE` / `DDEAUTO` | asks another application for data through Dynamic Data Exchange, starting that application if it is not running. `DDEAUTO` updates when the document opens. Abused since 2017 to start `cmd.exe` or `powershell` (Microsoft advisory ADV170021 then disabled DDE by default) |
| `INCLUDETEXT` | copies text, **with its fields**, from another document |
| `INCLUDEPICTURE` | shows a picture from a path or URL. Word writes this for pictures pasted from a web page |

In WordprocessingML (ECMA-376 Part 1, 17.16) an instruction is stored in one of two ways:
- the `w:instr` attribute of `w:fldSimple`;
- for a complex field, the `w:instrText` runs between `w:fldChar begin` and `separate`/`end`.

The second form can be split over any number of runs. Fields nest: an inner field's *result*
becomes part of the outer instruction. That is how the known DDE obfuscation builds
`cmd.exe` out of `QUOTE 99 109 100 ...` character codes.

## 2. What C7 does

1. It handles a package only if its main part is a WordprocessingML document or template
   (DOCX, DOCM, DOTX, DOTM). Every other file is `not_applicable`. A broken package fails
   closed, through the same OPC reader as `ooxml-links`.
2. It reads every XML part Word reaches through relationships (`ooxml_links.loaded_parts`):
   body, headers, footers, notes, comments, glossary, under any part name. It reads only the
   two WordprocessingML namespaces.
3. It reassembles each instruction across runs, keeping apart text inside tracked deletions
   (`w:delInstrText`, or anything inside `w:del`/`w:moveFrom`). Only the *live* text is
   classified (Section 2.1). A nested field becomes a placeholder, because
   its result does not exist until Word updates it.
4. It tokenises the instruction as Word does (17.16.1):
   - quoted and unquoted arguments, with `\\` and `\"` unescaped;
   - the arguments end at the first switch (`\d`, `\* MERGEFORMAT`).
5. It classifies the field by type and by its first argument (table below).

Nothing is evaluated, updated, fetched or resolved. The analysis is text parsing of XML,
through defusedxml and inside the isolated worker.

| Rule | Severity | When |
|---|---|---|
| `ENGINE_WORD_DDEAUTO_PROGRAM` | HIGH | `DDEAUTO` whose application is a program: a path, an executable or script extension, a command interpreter or script host (`cmd`, `powershell`, `mshta`, `wscript`, `rundll32`, ...), or built by a nested field |
| `ENGINE_WORD_DDE_PROGRAM` | MEDIUM | the same with `DDE`, which updates only when fields are updated |
| `ENGINE_WORD_DDE_APPLICATION` | LOW | `DDE`/`DDEAUTO` naming a DDE server by name (`Excel`), or nothing |
| `ENGINE_WORD_REMOTE_INCLUDE` | MEDIUM | `INCLUDETEXT` from a URL, UNC path, file URI with a host, another scheme, or a nested field; `INCLUDEPICTURE` from a network file path, another scheme or a nested field |
| `ENGINE_WORD_WEB_PICTURE` | INFO | `INCLUDEPICTURE` from http(s)/ftp |
| `ENGINE_WORD_LOCAL_INCLUDE` | INFO | either include field from a drive path that names no host (RFC 8089, `app.engine.file_paths`) or a relative path |
| `ENGINE_WORD_DELETED_INSTRUCTION` | INFO | instruction text in tracked deletions that, restored, would give one of the rules above: recorded, no execution claimed (Section 2.1) |
| `ENGINE_WORD_FIELDS_UNDETERMINED` | INFO | a loaded part unreadable or malformed, a field type built by a nested field, or an imported chunk (`w:altChunk`) present |

`INCLUDE` and `IMPORT`, the old names, count as `INCLUDETEXT` and `INCLUDEPICTURE`. All other
field types (PAGE, TOC, PAGEREF, HYPERLINK, MERGEFIELD, ...) are not reported.

**Why these severities.** They follow the policy of the other engine components: severity is what
the evidence shows the field can do, not a guess that Word will do it. Word asks before updating
links or starting a DDE server, and the defaults depend on version and policy.
- `DDEAUTO` naming a program is the direct request to start a command when the document
  opens. It is rated like an automatic PDF `/Launch` (`ENGINE_PDF_AUTO_CHAIN_LAUNCH`, HIGH).
- A remote `INCLUDETEXT` brings another document's content and fields into this one.
- A UNC lookup can send the user's Windows credentials, as `OFFICE_EXTERNAL_NETWORK_PATH` already
  rates (MEDIUM).
- A web picture is what Word itself writes for pasted web content, and is at most a web beacon.
  It is rated like `ENGINE_OFFICE_LINKED_PICTURE` (INFO), so ordinary documents copied from a
  browser are not flagged.

### 2.1 Tracked deletions: presence is not evaluation

The first C7 version (`4a598f1`) joined deleted instruction text into the field and classified
the result, so a `DDEAUTO cmd` that a reviewer had deleted was reported HIGH. That claimed more
than the evidence shows.

ECMA-376 Part 1, 17.13.5 defines `w:del` and `w:moveFrom` as content removed in a tracked
revision, and `w:delInstrText` as field-code text so removed. That text is not part of the
document as it now stands. It comes back only if a reviewer rejects the deletion, which is a
user action. From the release-freeze revision of C7 on (the commit that added this section):
- each field is classified on its **live** text alone: text outside deletions, insertions
  (`w:ins`, `w:moveTo`) included;
- a field whose begin is inside a deletion is entirely deleted;
- deleted text gives only `ENGINE_WORD_DELETED_INSTRUCTION` (INFO), and only when restoring it
  would change the classification. Its evidence says what the field would read as with the
  deletion rejected. It claims nothing about execution.

Whether Word evaluates a field while the document is under review was not observed. A deletion
can also change the live text: removing a space between `DDE` and `AUTO cmd` leaves a live
`DDEAUTO cmd`, which is HIGH, because that is what the document now says. Regression tests:
`test_instructions_only_in_tracked_deletions_are_recorded_without_an_execution_claim` (five
forms) and `test_live_text_is_classified_and_a_deletion_that_would_change_it_is_noted`.

## 3. Relation to the original four scanners

The reference Office scanner already reports any `DDEAUTO` (`OFFICE_DDEAUTO_FIELD`, HIGH) and
`DDE` (`OFFICE_DDE_FIELD`, MEDIUM). It reads the parts named `word/document`, `header*`,
`footer*`, `footnotes` and `endnotes`. **C7 is purely additive**: it accounts for no reference
finding, so the reference findings stand in the unified engine whatever C7 concludes. A
`DDEAUTO Excel ...` stays HIGH there, though C7 rates it LOW. The reference scanners, and their
results, are unchanged.

What C7 adds, each shown by a regression test against the reference engine
(`test_what_c7_adds_to_the_reference_engine`):

| Inert test document | Reference | Unified |
|---|---|---|
| `DDEAUTO` built with a nested `QUOTE` field | SAFE (its reassembly restarts at the nested begin and loses the outer type) | MALICIOUS |
| `DDEAUTO cmd` only in a tracked deletion | SAFE | SAFE (INFO: recorded, no execution claimed) |
| `DDEAUTO cmd` in a header Word loads from `word/parts/h.xml` | SAFE (not a name it reads) | MALICIOUS |
| `INCLUDETEXT` from `https://example.invalid/` | SAFE | SUSPICIOUS |
| `INCLUDEPICTURE` from `\\server.invalid\` | SAFE | SUSPICIOUS |
| `INCLUDEPICTURE` from `https://example.invalid/` | SAFE | SAFE (INFO evidence only) |

The reverse case: a `DDEAUTO` in a part no relationship leads to (which Word never reads) is
reported by the reference and not by C7, and stays HIGH in the unified engine.

## 4. Validation

| Check | Result (commit of this document) |
|---|---|
| Unit and regression tests (`tests/test_word_fields.py`) | 69 pass: reassembly across runs, nesting, tracked deletions and insertions, unterminated fields, strict namespace, foreign namespace ignored, tokenising and escapes, every rule, fields not reported, loaded vs unloaded parts, malformed parts, `altChunk`, non-Word files, both engines, the isolated worker |
| Existing evaluation: 16 synthetic, 29 + 4 benign corpus, 2 corrupt, both engines | 102 of 102 results identical to the frozen Windows evidence (verdict and every finding, INFO included); 9 of 9 contribution claims pass (`evaluation.offline_validation` logic, run in-process) |
| C7 evaluation cases (`evaluation.cases.field_cases`, set `c7` of `evaluation.offline_validation`) | 6 inert DOCX: nested DDEAUTO, plain DDEAUTO, remote INCLUDETEXT, file-share INCLUDEPICTURE, DDEAUTO only in a deletion, ordinary fields. In-process (`tests/test_offline_validation.py::test_every_claim_and_expected_result_holds_in_process`, every commit, Windows and Linux CI): 12 of 12 verdicts as expected, 11 of 11 claims. Through the real isolated worker in the offline VM, final run 3 at `eda2a08`: 12 of 12 C7 verdicts as expected and both C7 claims PASS, under strict isolation ([evidence/final-eda2a08-run3/](evidence/final-eda2a08-run3/README.md); `docs/offline-vm-validation-phase6.md`, Section 7) |
| Benign corpus | fields present only in `docx-02` (`TOC`, `PAGEREF`), parsed and not reported; no C7 finding on any corpus file |
| `word-fields` status | `completed` on the 8 DOCX cases and 7 corpus DOCX, `not_applicable` on PDF, XLSX, PPTX; `failed` on the truncated DOCX (fails closed, like `office`, `custom`, `vba-chains`, `ooxml-links`) |
| Full suite | Windows: 933 passed, 38 skipped (Linux-only tests). Linux CI, Python 3.11, commit `4a598f1` ([run 42551205597](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/42551205597)): 971 passed, 0 skipped |

The frozen evidence (`docs/evidence/custom-engine-fp-fixes/`) is not regenerated: it records the
engine before C7. `tests/test_api_engines.py` compares its scanner statuses without `word-fields`,
whose status is pinned in `tests/test_word_fields.py` instead.

## 5. Limitations

- **Static and partial by design.** C7 reads what an instruction says. It never computes a
  nested field. A target or application built by one is therefore *unknown*, and is treated as
  the worse case (program, or remote).
- **Arguments after a switch** are not read (Word puts switches after the arguments in what it
  writes, but the syntax allows otherwise). Only the first argument is classified.
- **Not covered:**
  - other formats: RTF (`\field`, `\fldinst`; the reference YARA rule `RTF_DDE_Auto_Field` covers
    `DDEAUTO` there), binary `.doc`, Excel DDE (`OFFICE_DDE_LINK`, `=cmd|...` formulas), and
    PowerPoint;
  - other fields that reach outside: `LINK` (an OLE link written as a field), `HYPERLINK`
    (click only), `MERGEFIELD` data sources, `DATABASE`;
  - imported chunks (`w:altChunk`): reported as undetermined, not analysed;
  - the `w:updateFields` setting (update fields on open), which is not used to raise severity.
- **Tracked changes** are read as the document now stands (Section 2.1). Word's behaviour on
  fields during review, and on fields whose live text is unusual after a deletion, was not observed.
- **Unloaded parts are ignored**: fields there are not reported by C7 (Word does not read them;
  the reference still reports DDE there).
- **No Office runtime is observed.** Whether Word prompts, blocks or updates a field depends on
  version, Trust Center settings, Protected View and policy.
- **Evidence is synthetic.** The test documents are built from strings, never opened in Word,
  and contain no working command. No real DDE or include-field malware was analysed. Accuracy on
  real samples is not measured.
