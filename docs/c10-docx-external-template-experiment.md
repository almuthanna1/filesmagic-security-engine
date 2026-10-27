# Controlled document-attack experiment: Word external-template indicator (C10)

**Run 2026-10-27, offline research VM, inert synthetic files only.** No genuine malware was used,
nothing was executed and no network was available. The external template points at the reserved
`.invalid` domain, which can never resolve, and no macro is involved.

## Question

For one common Word attack technique, a document that loads an **external template** when it is
opened (an OOXML `attachedTemplate` relationship with `TargetMode="External"`), which of the
engine's three tools detect it, and which do not? The comparison is against a harmless Word
control.

## Setup

| Item | Value |
|---|---|
| Environment | VM `FilesMagic-securityLAB`, Ubuntu 24.04.5, kernel 7.0.0-38, 4 vCPU; **no network adapters**; validated snapshot `36c2d7f6-decc-49fd-91a4-434ff0aa02e6` as parent |
| Engine | commit `b1a69462c9593e81d02ab290410da026f26071c9`; rule set `0be9918509e9…`; yara-x 1.21.0, oletools 0.60.2, pypdf 6.19.0 |
| Isolation | Strict mode (`SECURITY_ENGINE_REQUIRE_ISOLATION=1`); root-owned Python 3.11.18 confined by AppArmor profile `filesmagic-eval-python` (enforce) |
| Control | `control-harmless.docx`, 833 B, SHA-256 `f9eee47044ea83303bbd11b479ff9b49d58d602299fb6efdcbe8ac7d93483f89`; built by the repository's `tests/office_fixtures.make_ooxml({})` |
| Indicator | `external-template.docx`, 1,161 B, SHA-256 `42ef81bc3d45042c7418c78729efdada76973126399d8a44e544567f29c32969`. A **harmless synthetic test file, not genuine malware**: the same builder plus `word/_rels/document.xml.rels` with `attachedTemplate` → `https://example.invalid/template.dotm` (External), and no payload |
| Labels | Control `BENIGN`; indicator `SECURITY_TEST`. Both labels come from how the files were constructed; neither is real-world ground truth |

**Measurements:**

1. **Strict harness:** run five times, each with its own strict preflight. Each run records the
   verdict, completeness, per-scanner status, findings, isolation evidence and wall-clock time per
   sample, which includes starting a fresh worker.
2. **Per-tool timing:** each scanner called in-process under the same confined interpreter, outside
   the worker: one warm-up, then 20 timed calls per file. These are scanner-only times.

## Results

**Strict harness:**

- Five of five runs `completed`. Every preflight was SAFE, complete and `isolation_missing=[]`.
  Preflight requests: `0db6d529fac34efd`, `359ba7436b664181`, `f5ab02bd3df24713`,
  `bbaf4301539f47a5`, `479fbd063b24472b`.
- Every sample in every run had verified isolation.

| File | Verdict (5/5 runs) | Complete | Findings | Scanner status | Wall-clock per sample, median (min-max), n=5 |
|---|---|---|---|---|---|
| Control | **SAFE** | yes | none | YARA-X completed, Office completed, PDF not applicable | 262.3 ms (195.7-351.8) |
| External template | **SUSPICIOUS** | yes | `OFFICE_EXTERNAL_AUTOLOAD` (MEDIUM) | YARA-X completed, Office completed, PDF not applicable | 256.1 ms (204.8-382.0) |

**Per tool** (scanner-only, median of 20, with min-max):

| Tool | Control | External template | Detects the indicator? |
|---|---|---|---|
| YARA-X (raw-byte rules) | completed, no finding; 0.237 ms (0.205-0.632) | completed, **no finding**; 0.218 ms (0.198-0.402) | **No** |
| Office structural analysis | completed, no finding; 0.136 ms (0.107-0.364) | completed, **`OFFICE_EXTERNAL_AUTOLOAD` (MEDIUM)**; 0.177 ms (0.157-0.384) | **Yes** |
| PDF structural analysis | not applicable; ≈0 ms | not applicable; ≈0.001 ms | Not applicable (not a PDF) |

**Why YARA-X had no finding for this technique.** This is a result for this one technique under
the current rule set (`0be9918509e9…`). It is not evidence of a general malware-detection
failure. Two diagnostics show the cause:

- the string `attachedTemplate` does not appear in the raw `.docx` bytes, because the relationship
  XML is deflate-compressed inside the ZIP container;
- even when YARA-X scans the **uncompressed** relationship part, the current rule set returns no
  match.

So it misses for two reasons: there is no rule for this technique, and compression hides the
relevant text from raw-byte matching. The Office scanner detects it because it opens the package
and parses the relationship itself.

## Interpretation

- **Complementary layers.** The detection came from structure-aware parsing, not signatures. The
  layered design matters: for this technique, the current raw-byte rules alone would have passed
  the file as SAFE.
- **Verdict.** The indicator produced `SUSPICIOUS`, not `MALICIOUS`: an external template is
  risky, but also used legitimately, so the rule is MEDIUM severity. Under the intended
  security-first workflow ([security-first-architecture.md](security-first-architecture.md)),
  this file would **not** be passed to conversion, while the control would.
- **Performance.** There are two different measurements here:
  - **Scanner-only time:** each scanner takes well under 1 ms per file, measured in-process
    without the worker.
  - **End-to-end time:** the harness's 0.2-0.4 s per sample includes starting a fresh isolated
    worker, so most of it is worker start-up.

  These VM figures are **not** a controlled comparison with the roughly 6-7 s per scan seen on
  Render Free (0.1 CPU) in earlier phases. The hardware, the files and the measurement paths all
  differ.

## Limitations

- **One technique, two files, synthetic construction.** This shows functional behaviour. It is not
  a detection rate, false-positive rate or accuracy measurement.
- **Real attack documents** often differ: obfuscated or relative targets, other relationship
  types, or templates delivered through other parts. Coverage of those isn't shown here.
- **Timing scope.** Harness timings come from 5 runs on one VM; per-tool timings are in-process,
  without the worker. Neither is a benchmark.
- **No outside tool.** No external antivirus (for example ClamAV) was compared, because none is
  installed in the offline VM.

## Evidence (inside the VM; not exported)

- `~/fm-eval/results/c10-docx-run1` … `run5`: `run_status.json`, `per_sample.csv/json`,
  `summary.json/md`. Run logs are in `c10-logs/`.
- `~/fm-eval/results/c10-per-tool.json` and `~/fm-eval/results/c10-harness-summary.json`.
- `~/fm-eval/manifest.csv` (C10). The earlier C9.2C manifest is preserved as
  `manifest.c92c.csv`.
- The scripts are in `~/c92c/`: `make_docx_experiment.py`, `per_tool.py`, `summarize_runs.py`.
