# Offline single-sample results viewer: plan (proposed)

| | |
|---|---|
| Status | Proposal. Nothing implemented, transferred or scanned. Validation will use inert fixtures only. |
| Date | 2026-11-09 |
| Purpose | Inspect the first genuine-malware result ([Emotet pre-registration](malware-eval-e50c941c-preregistration.md)) inside the offline Ubuntu VM, with no network, no hosted service and no upload |
| Release | `custom-engine-freeze-2026-11-09` (`2d586f6`): detection logic unchanged |

## 1. Decision: do not run the Security Lab UI in the VM; generate a static report

The Lab (`frontend/`: Next.js 16.4.3, React 19.3, the scan-token route, `lib/api.ts`) **could**
be run on localhost, but it is the wrong tool for a live sample:

| Lab property | Consequence in the VM |
|---|---|
| The **browser** reads the file: a GTK file picker selects it, `sha256Hex()` loads all of its bytes into the browser, and `fetch` POSTs them to the API | Firefox and the GTK file chooser become parsers of the sample, outside the worker, the AppArmor profile and strict isolation. The file chooser can render previews and thumbnails of the sample folder. |
| Needs Node.js plus `node_modules` (hundreds of packages), `next build` and a running uvicorn API | Everything must come in by ISO (the VM has no network). It adds a large unvalidated attack surface, and the API process is not the confined evaluation interpreter. |
| Needs `LAB_SCAN_TOKEN_PRIVATE_KEY` and the engine's public key | New secrets in the VM for no security benefit (single user, no network) |
| `/test-files` serves fixture bytes (`app/test-files/download/[id]`) | The kind of "serve sample bytes" path the requirements forbid |
| Designed for public staging (Vercel + Render) | Must stay unchanged; any local variant would be a fork of it |

**Simpler and safer:** the existing offline harness already runs both engines through
`app.worker.run` with every research gate. A small evaluation-only script adds one sample and
writes a **self-contained static HTML report** (no JavaScript, no external resources), viewed in
the VM's browser from `file://`. The report holds only metadata, so the browser never touches the
sample. The bytes are read once, by the confined Python process, and passed to the worker in memory.

## 2. What already exists and is reused unchanged

| Piece | Location | Gives |
|---|---|---|
| Research gates | `evaluation/offline_validation.py` `gates()`, `confinement()`; `evaluation/benchmark.py` `research_checks()`, `host_network()`, `dependency_drift()` | strict isolation configured; interpreter confined by `filesmagic-eval-python (enforce)`; no usable route; expected commit, clean tree; packages = `requirements.txt` |
| Preflight per engine | same file, empty input via `synthetic.scan_case` | nothing is parsed unless every isolation control is present and the worker runs exactly that engine's scanners |
| Scan with trials | `evaluation/cases.py` `scan_case(item, trials, cmd)` | per engine: verdicts (aggregate and per scanner), all findings, scanner status, `isolation_missing` across **all** trials, determinism, wall and per-scanner latency (median/p95) |
| Engine selection | `worker.command() + worker.ENGINE_ARGS[engine]` | reference and unified: no change to `evaluate.py` needed |
| Session controls | `python -m evaluation.offline_validation` | inert sets, 114/114 expected (run 3) |

## 3. The only new code: `evaluation/single_sample.py` (about 100 lines, evaluation-only)

On a new branch `research/offline-single-sample` from the tag. `git diff custom-engine-freeze-2026-11-09 -- app/`
must be empty (checked by the script itself, and in CI).

```
SECURITY_ENGINE_REQUIRE_ISOLATION=1 /opt/filesmagic/venv/bin/python -B -m evaluation.single_sample \
    --sample ~/fm-eval/samples/malicious/<id>.bin --sha256 <expected> \
    --expectations evaluation/expectations/<id>.json --expect-commit <sha> --trials 5 \
    --out ~/fm-eval/results/single-<id>-<sha7>
```

(As implemented: the predictions are a committed JSON copy of the pre-registration, which names
the pre-registration file and is hashed into the results; `~/fm-eval/samples/**` is the path
the AppArmor profile lets the interpreter read.)

Steps, stopping at the first failure (exit 3, `run_status.json` written):
1. Refuse if `--out` exists (results are never overwritten).
2. `gates()` from offline_validation, plus: `app/` is identical to the tag (`git diff --quiet <tag> -- app/`).
3. Record the SHA-256 of the pre-registration file. The script **never writes to it**; the report links
   it as "expected" and shows the actual result separately.
4. Read the sample **once** into memory (`Path.read_bytes`, size ≤ 10 MB, the upload limit) and compare
   its SHA-256 with `--sha256`. A mismatch stops before any scan. No copy, no temporary file, no rename.
5. Preflight both engines (empty input), as offline_validation does.
6. `scan_case` for `reference` then `unified`, N trials each; `scan_problem()` after each.
7. Write:
   - `results.json` (full metadata);
   - `report.html`;
   - `SHA256SUMS`.

   Redaction: findings and evidence are passed through one function that replaces URL, UNC and
   `file:` patterns and anything over 200 characters with `[redacted sha256:…]`.

`report.html` (standard library: `html.escape`, one inline `<style>`;
`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`):
- the sample's ID, SHA-256 (expected and observed), size, commit, rule-set hashes, AppArmor label, host network check;
- the pre-registered predictions from `evaluation/expectations/<id>.json` (verdicts, rules, the P5
  alternative, scanners not applicable, determinism, isolation, latency bound), each marked held or
  not held next to the actual result, with the SHA-256 of the expectations and of the pre-registration;
- per engine: verdict per trial, findings (scanner, rule, severity, redacted description), scanner status
  (completed / not applicable / failed with kind), isolation controls with every required control and
  `isolation_missing`, latency (wall and per scanner, median/p95/max), determinism;
- the reference-vs-unified difference, flagged as **D1** if the unified verdict is lower.

The actual results are written only to the new results folder. Section 5 of the pre-registration is
filled afterwards, by a person, from `results.json`: a separate commit, the predictions untouched.

Test (CI and Windows, inert only), one file `tests/test_single_sample.py`:
- a hash mismatch stops before any scan;
- an existing `--out` is refused;
- redaction removes URL and UNC patterns;
- the report has no `<script>` and no external reference;
- a run on an inert generated legacy .doc (`tests/office_fixtures.make_ole` with `WordDocument` and an
  empty `Macros/VBA` storage, no code) produces both engines' sections. The repository has no inert .doc
  with real VBA source: the macro tests stub olevba.

The gates that need the VM (AppArmor, no route) are skipped only where measured, as
`tests/test_worker_linux.py` already does.

## 4. Inert validation (before any live file)

1. CI passes on the branch, and `app/` is unchanged compared with the tag.
2. A transfer ISO is built from the pushed branch tip (`evaluation/vm/build_transfer_iso.ps1`, unchanged).
   It is attached with the normal swap procedure, and the integrity checks 7/7 pass.
3. In the VM:
   - session control `offline_validation`, 114/114;
   - `single_sample` on **three inert fixtures**: the generated .doc with an empty VBA storage
     (it takes the same OLE and VBA path as the Emotet sample; expected SUSPICIOUS:
     `OLE_Office_VBA_Macros` MEDIUM and `OFFICE_VBA_UNPARSED` LOW, to be confirmed in CI first),
     one benign corpus document (SAFE), one truncated document (UNABLE_TO_SCAN);
   - a deliberate hash mismatch (STOP);
   - `report.html` opened from `file://`.
4. Results are copied out by Guest Control `copyfrom` and committed as evidence, and the run is
   recorded in the readiness report.

This proves the workflow, the gates and the report, without any live file.

## 5. Indexing, thumbnailing, previewing and uncontrolled parsing

| Risk | Where | Control |
|---|---|---|
| Tracker (GNOME search) extracts metadata from new files: Office via `libgsf`, PDF via `poppler` | any indexed folder, including removable media | sample folder outside indexed locations; `tracker3 daemon --pause` or the Search setting turned off, **verified** (`tracker3 status`) before the medium is attached |
| Thumbnailers (`gnome-desktop` thumbnail factory, `evince-thumbnailer`, LibreOffice or `gsf-office-thumbnailer` if installed) | Files (Nautilus) windows, the GTK file chooser | never open the sample folder or the medium in Files or any file chooser; disable thumbnails ("Show thumbnails: Never") and check that `~/.cache/thumbnails` stays empty for the folder |
| Preview (Files' space-bar preview by `sushi`, Evince, LibreOffice by double-click) | desktop | not used; no default-application opening; the sample keeps a neutral name with no `.doc` extension (`<id>.bin`) |
| Auto-mount of the medium (seen in runs 2–3) | GNOME and udisks | the medium carries only the **encrypted** archive, so a desktop process sees ciphertext; it is unmounted and ejected right after copying |
| Browser parsing | Firefox | only the metadata report is opened; the Lab UI is not used (Section 1) |
| `file`, `less`, `strings`, `cat` on the sample | terminal habit | not used; only `sha256sum` and the script |
| Extraction | 7-Zip | the only parser of the sample outside the worker: a hash-pinned binary, runs on the AES ZIP only, into a `noexec` folder; that is the documented residual risk |
| Analysis | `scan_case` worker | namespaces, capability drop, rlimits, audit hook, strict mode, AppArmor; the residual risks of C9.2 Section 7 apply (shared uid and profile, results and `/tmp` writable) |

## 6. Acquisition and offline transfer prerequisites (before any live file)

Order, each step needing the approval named:

| # | Step | Approval |
|---|---|---|
| 1 | Approval of Dr. Haque recorded in writing in handling procedure §12 **with its scope**: this sample, this plan, and the named equipment (personal laptop and VM `FilesMagic-securityLAB`) | Dr. Haque |
| 2 | NIU determination for a **personal device** (see Section 7) | NIU IT security / research compliance |
| 3 | Host checks recorded: BitLocker on the volume of the VM and `C:\fm-samples\`; VirtualBox current maintenance release; Defender on, no new exclusions | researcher |
| 4 | MalwareBazaar terms and Auth-Key; vendor table of the pre-registration filled in; label basis met | researcher |
| 5 | Inert validation of Section 4 passed | researcher |
| 6 | Download the AES ZIP by API (command line, not a browser) into `C:\fm-samples\` (outside OneDrive, not indexed); verify the archive's hash; custody log entry; never decrypted on Windows | researcher's go-ahead |
| 7 | Build the **sample ISO** with a separate builder (archive, manifest, `SHA256SUMS`, pinned 7-Zip); it refuses any decrypted Office/PDF file; it is never placed in the repository or OneDrive | go-ahead; builder reviewed first |
| 8 | VM: "Pre-sample baseline" snapshot; Tracker and thumbnails off and verified; `noexec` mount (the user runs the one `sudo mount`); network adapters remain **unattached** and the settings diff is empty | go-ahead per item |
| 9 | Session: attach the ISO → copy the archive → unmount and eject → extract → verify SHA-256 → control 114/114 → `single_sample` → control 114/114 → `copyfrom` of the results folder only | go-ahead |
| 10 | Power off → restore the baseline → `emptydrive` → settings diff → delete the archive and ISO on the host → close the custody log | go-ahead |

## 7. Which approvals cover the personal laptop and VM

- **Dr. Haque's approval** covers the research activity and its supervision. It covers the personal
  laptop and VM **only if the written approval names them**. Handling procedure §2 row 1 and §12 are
  still blank, so the scope should be recorded there.
- **It does not replace NIU's determination** (handling procedure §2 row 2). Using a personally owned
  device for live malware is an institutional question: whether it is permitted, and under which
  conditions (encryption, no university network or data on the device, retention, incident reporting).
  Only NIU IT security or research compliance can answer it; the office still has to be identified
  with Dr. Haque. If NIU requires university equipment, this plan moves unchanged to an NIU machine,
  which then repeats the inert validation of Section 4.
- **The VM's existing validation** (runs 1–3, C9.2) shows that the controls are applied. It does not
  prove containment of a hostile file, which stays a documented residual risk accepted by the approvers.
- **Not involved:** Vercel, Render, GitHub (metadata only), production FilesMagic, IRB (to confirm).

## 8. Effort

About half a day: the script and its test, CI, and one inert VM run. It does not change the
engine, the Lab or production, and it is useful for every later sample of the plan.
