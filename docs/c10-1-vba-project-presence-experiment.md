# Controlled document-attack experiment: Word VBA macro-project presence (C10.1)

**Run 2026-10-27, offline research VM, inert synthetic files only.** No genuine malware was
used, **no macro was created or executed**, and no network was available. The indicator carries
a structural VBA-project marker with **no valid or compiled macro and no AutoOpen code**.

## What this experiment does and does not show

- **Shows:** whether the engine statically detects the *presence of a VBA macro-project
  structure* inside a DOCM-shaped package, and which of the three tools detect it.
- **Does NOT show:** detection of VBA **AutoOpen / auto-execution**. The fixture contains no
  compiled macro, so there is no `AutoOpen`/`Document_Open` code to detect and nothing was
  executed. The engine's auto-execution finding (`OFFICE_MACRO_AUTOEXEC`) is produced only when
  olevba parses a genuine compiled VBA project, which is outside the inert-synthetic scope of
  this experiment. This is **static structure detection, not execution detection**.

## Question

For the macro-delivery technique (a document that carries a `word/vbaProject.bin` VBA project),
which of the engine's three tools detect the macro-project *structure*, and how does that compare
with the external-template technique from the C10 experiment? The comparison is against a
harmless Word control.

## Setup

| Item | Value |
|---|---|
| Environment | VM `FilesMagic-securityLAB`, Ubuntu 24.04.5, kernel 7.0.0-38, 4 vCPU; **no network adapters**; validated snapshot `36c2d7f6-decc-49fd-91a4-434ff0aa02e6` lineage |
| Engine | commit `b1a69462c9593e81d02ab290410da026f26071c9`; rule set `0be9918509e9…`; yara-x 1.21.0, oletools 0.60.2, pypdf 6.19.0 (same engine and rules as C10) |
| Isolation | Strict mode (`SECURITY_ENGINE_REQUIRE_ISOLATION=1`); root-owned Python 3.11.18 confined by AppArmor profile `filesmagic-eval-python` (**enforce**, confirmed label `filesmagic-eval-python (enforce)`) |
| Control | `control-harmless.docx`, 833 B, SHA-256 `9dda2dc2cb72d6eaf860f8f5ada16602da48dc87bf4b4972005efd5dc5e3eb02`; built by `tests/office_fixtures.make_ooxml({})` |
| Indicator | `vba-storage.docm`, 1,127 B, SHA-256 `09785dabeeab93a34d0853d7f64c8127cbc1ff43330405189665789044307690`. A **harmless synthetic test file, not genuine malware**: `make_ooxml({"word/vbaProject.bin": make_ole({"VBA/dir": b"x"})})` — a DOCM-shaped package carrying a VBA **storage** with no valid/compiled macro and no AutoOpen code. This is the repository's own inert VBA fixture construction (`tests/test_office.py`) |
| Labels | Control `BENIGN`; indicator `SECURITY_TEST`. Both labels come from how the files were constructed; neither is real-world ground truth |

**Measurements:** identical methodology to C10 — (1) strict harness, 5 runs each with its own
strict preflight; (2) per-tool scanner-only timing, 1 warm-up + 20 timed calls per file under the
confined interpreter.

## Results

**Strict harness:**

- Five of five runs `completed` (exit 0). Every preflight was SAFE, complete and
  `isolation_missing=[]`. Preflight request IDs: `3ac89d3eb3e04b5f`, `27c8cbad82604b3a`,
  `62ae9ec15d3d4a54`, `1b5e59044cdf457a`, `414b387b892e4df1`.
- Every sample in every run had verified isolation (`isolation_missing=[]`), including
  `net_loopback_only=true` and all capability/rlimit/audit controls.

| File | Verdict (5/5 runs) | Complete | Findings (rule IDs) | Scanner status | End-to-end per sample, median (min–max), n=5 |
|---|---|---|---|---|---|
| Control | **SAFE** | yes | none | yara-x completed, office completed, pdf not_applicable | 254.5 ms (247.9–472.2) |
| VBA storage | **SUSPICIOUS** | yes | `OFFICE_VBA_UNPARSED` (LOW) + `OOXML_VBA_Macros` (MEDIUM) | yara-x completed, office completed, pdf not_applicable | 262.8 ms (206.9–482.0) |

Per-sample request IDs — control: `38f399d801804335`, `98bd3122c3dc48d7`, `8934f7b428684659`,
`2102fe8ac138428d`, `009cf56569464234`; indicator: `2c1cb5cdbbef4d7c`, `3f4e9f3e5bc142f5`,
`93ab993533e7499c`, `b1effd6b5bf04b10`, `d24e06f0a8ef4c15`.

**Per tool** (scanner-only, median of 20, with min–max):

| Tool | Control | VBA storage | Detects the indicator? |
|---|---|---|---|
| YARA-X (raw-byte rules) | completed, no finding; 0.284 ms (0.206–1.686) | completed, **`OOXML_VBA_Macros` (MEDIUM)**; 0.251 ms (0.215–0.606) | **Yes** |
| Office structural analysis | completed, no finding; 0.127 ms (0.107–0.463) | completed, **`OFFICE_VBA_UNPARSED` (LOW)**; 0.923 ms (0.293–3.089) | **Yes** |
| PDF structural analysis | not applicable; ≈0 ms | not applicable; ≈0.001 ms | Not applicable (not a PDF) |

Diagnostic: `raw_bytes_contain_vbaProject_bin: True`; `raw_bytes_contain_VBA_PROJECT: False`.

**Why both layers detect it here (unlike C10).** YARA-X matches because the rule
`OOXML_VBA_Macros` looks for the literal string `vbaProject.bin`, which is a **ZIP entry name
stored uncompressed** in the package's local/central headers — so it is visible to raw-byte
matching (`raw_bytes_contain_vbaProject_bin: True`). The Office scanner independently opens the
package, reads `word/vbaProject.bin`, recognises it as a VBA storage, and — finding no parseable
compiled project inside — reports `OFFICE_VBA_UNPARSED` (LOW): *"a VBA project storage that could
not be parsed."* It is **not** an auto-execution finding.

## Comparison with the C10 external-template experiment

Same engine commit and rule set, so the two are directly comparable.

| | C10 — external template (`external-template.docx`) | C10.1 — VBA storage (`vba-storage.docm`) |
|---|---|---|
| Malware technique represented | Remote-template auto-load on open (`attachedTemplate`, `TargetMode="External"`) | Macro delivery (document carries a VBA project) |
| YARA-X (raw bytes) | **No finding** — the relationship XML is deflate-**compressed** inside the ZIP, hiding `attachedTemplate` from raw bytes | **`OOXML_VBA_Macros`** — the marker `vbaProject.bin` is a ZIP entry **name**, stored uncompressed |
| Office structural analysis | **`OFFICE_EXTERNAL_AUTOLOAD`** (MEDIUM) | **`OFFICE_VBA_UNPARSED`** (LOW) |
| Which layer detected it | Structure-aware parsing only (layers **disagree**) | Both raw-byte and structure-aware (layers **agree**) |
| Verdict | SUSPICIOUS (MEDIUM) | SUSPICIOUS (MEDIUM) |
| Under the security-first workflow | Not passed to conversion | Not passed to conversion |

**Lesson across the two experiments.** Detection depends on *where in the container* an indicator
lives. A signature layer sees only uncompressed bytes (ZIP entry names, OLE stream magic); a
structure-aware parser sees inside compressed parts. C10 showed a case the signature layer missed;
C10.1 shows a case it catches. The layered design is what gives coverage of both — but neither
experiment is a detection-rate measurement.

## Interpretation

- **Structure, not execution.** The indicator is classified SUSPICIOUS because the engine detects
  a *macro-project structure*, not because it saw a macro run or found an `AutoOpen` keyword. The
  Office finding is literally "VBA storage present but unparseable" — there is no compiled macro in
  the fixture to parse. Distinguishing an attacker *shipping* a macro project from a macro
  *auto-executing* is the whole point of this caveat.
- **Verdict.** `SUSPICIOUS`, not `MALICIOUS`: a macro project present without parseable dangerous
  behaviour is MEDIUM at most. Under the intended security-first workflow
  ([security-first-architecture.md](security-first-architecture.md)), this file would **not** be
  passed to conversion; the control would.
- **Performance.** Two distinct measurements, as in C10:
  - **Scanner-only:** each scanner is well under 1 ms per file (Office is slightly slower on the
    indicator, 0.923 ms, because it opens the OLE storage).
  - **End-to-end:** the harness's ~0.25 s per sample is dominated by starting a fresh isolated
    worker. These VM figures are **not** a controlled comparison with Render's ~6–7 s/scan.

## Limitations

- **One technique, two files, synthetic construction.** Functional-behaviour demonstration, not a
  detection rate, false-positive rate or accuracy measurement.
- **No execution and no compiled macro.** This says nothing about whether the engine would flag a
  real AutoOpen macro's *behaviour*; that path (`OFFICE_MACRO_AUTOEXEC` via olevba on a genuine
  compiled project) is untested here and requires an approved real-sample procedure.
- **Timing scope.** Harness timings are 5 runs on one VM; per-tool timings are in-process without
  the worker. Neither is a benchmark.
- **No outside tool.** No external antivirus was compared; none is installed in the offline VM.

## Evidence (inside the VM; not exported)

- `~/fm-eval/results/c101-run1` … `run5`: `run_status.json`, `per_sample.csv/json`, `summary.*`.
  Run logs are in `~/fm-eval/results/c101-logs/`.
- `~/fm-eval/results/c101-per-tool.json`.
- `~/fm-eval/manifest.csv` (C10.1), preserved as `manifest.c101.csv`. The C10 manifest is
  preserved as `manifest.c10.csv`; the C9.2C manifest as `manifest.c92c.csv`.
- Scripts in `~/c92c/`: `make_vba_experiment.py`, `per_tool_vba.py`, `extract_c101.py`.
