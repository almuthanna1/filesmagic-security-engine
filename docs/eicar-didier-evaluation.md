# EICAR and Didier Stevens feature-detection study

Status (2026-11-03): **tooling implemented and tested; experiment not yet run.**
- The VM's isolation settings were corrected and verified (section 4).
- The four Didier Stevens files are acquired and verified, and 13 benign samples are prepared,
  outside the VM.
- EICAR has not been acquired.
- Still to do: transfer the code and samples into the VM, then the in-guest route check.

Requested by Dr. Nur Imtiazul Haque.

## 1. Question and labels

Which FilesMagic detection method (YARA-X, PDF Analysis, Office Analysis, Custom Scanner) identifies
which known document feature, compared with Didier Stevens' PDFiD as an independent reference, and
at what cost per scanner?

- Generated documents are labelled **BENIGN**: each carries an inert structural indicator (for
  example JavaScript that only calls `app.alert`), present by construction. A detection shows that
  a method recognises a structure, **not** that it detects malware.
- EICAR is labelled **SECURITY_TEST**. It is an agreed anti-malware test string, not a document.
  FilesMagic has no EICAR rule, and the rules are **not** changed to create one: whatever the
  engine reports (expected: SAFE, 1 of 4 scanners applicable) is the result. PDF and Office
  Analysis do not apply to it.
- No accuracy, precision or recall figures are derived from this study.

## 2. Allowlist (for approval)

Source of truth: [evaluation/allowlist.json](../evaluation/allowlist.json). Only these six files, over
HTTPS, no redirects, size- and SHA-256-checked before they are kept.

| ID | URL | Size | Pin | Role |
|---|---|---|---|---|
| eicar-com-txt | https://secure.eicar.org/eicar.com.txt | 68 | SHA-256 `275a021b…51fd0f` (the canonical test string) | security test file |
| eicar-com-zip | https://secure.eicar.org/eicar_com.zip | 184 | exactly one member `eicar.com`, 68 bytes, same SHA-256; the archive's own hash is recorded at acquisition (EICAR publishes none) | security test file in an archive |
| ds-pdfid | raw.githubusercontent.com/DidierStevens/DidierStevensSuite/**7d625d0**/pdfid.py | 45194 | SHA-256 `e958a01f…f1248f`, git blob verified | independent reference |
| ds-mpdf | …/7d625d0/mPDF.py | 25658 | SHA-256 `d241d767…e2b6de` | PDF writer library |
| ds-make-pdf-javascript | …/7d625d0/make-pdf-javascript.py | 4043 | SHA-256 `6b5bc2d6…039651` | generator |
| ds-make-pdf-embedded | …/7d625d0/make-pdf-embedded.py | 5392 | SHA-256 `5ae80ab1…371189` | generator |

**Review of active content: none of the selected materials needs any document content to be
executed.**

- **EICAR**: plain ASCII, never executed.
- **The four Didier Stevens files** were read in full at the pinned commit. They are Python source
  that uses only the standard library and is public domain ("Source code put in public domain by
  Didier Stevens, no Copyright").
  - `make-pdf-javascript.py` only writes PDF text. Its default script is
    `app.alert({cMsg: 'Hello from PDF JavaScript', …})`, which nothing in this study runs.
  - `make-pdf-embedded.py` would add launch JavaScript (`exportDataObject … nLaunch: 2`) only with
    `-a` or `-b`. `prepare_samples.py` refuses both options in every spelling `optparse` accepts
    (`-ab`, `--auto`, …), and the embedded file is an inert text note.
  - `make-pdf-embedded.py` is run with `-f h -n note.txt`. Its default FlateDecode path fails on
    Python 3 because of an upstream bug (`mPDF.appendBinary` calls `bytes(bytes, 'ascii')`), and
    ASCIIHexDecode avoids it. Without `-n`, the tool would write the local file path into the PDF.
  - `pdfid.py` can fetch URLs, open archives protected with the password "infected", `eval()` its
    `-S` option and `exec()` plugins. It is called only as a library
    (`PDFiD`/`PDFiD2JSON`, `disarm=False`) on local `.pdf` paths, so none of those code paths is
    reachable.

**Excluded:**
- Didier Stevens' PDF-with-DOC macro dropper, and every third-party sample document.
- `eicar.com`: a duplicate of `eicar.com.txt`.
- `eicar_com2.zip`: a nested archive.
- `make-pdf-helloworld.py`: Python 2 only. Its clean PDF is built by calling `mPDF` directly.
- `pdf-parser.py` and the blog's ZIP bundles, whose contents were not reviewed.
- Every password-protected archive.

## 3. Samples

Built by `evaluation/prepare_samples.py`. The manifest's `source` column keeps the three origins
apart; `tags` lists each sample's expected features.

| Sample | Source | Expected features |
|---|---|---|
| pdf-clean-local, docx-clean-local, xlsx-clean-local, pptx-clean-local, docx-external-hyperlink-local | generated-local | none (negative controls) |
| pdf-js-openaction-local | generated-local | pdf-javascript, pdf-auto-action |
| pdf-js-obfuscated-local, pdf-js-obfuscated-objstm-local | generated-local | + pdf-name-obfuscation |
| docx-external-template-local (`https://template.example.invalid/…`, never fetched) | generated-local | office-external-autoload |
| docx-macro-declaration-mismatch-local (placeholder text, no VBA) | generated-local | office-macro-project, office-macro-declaration-mismatch |
| pdf-clean-didier | generated-didier-stevens | none |
| pdf-js-didier | generated-didier-stevens | pdf-javascript, pdf-auto-action |
| pdf-embedded-didier | generated-didier-stevens | pdf-embedded-file |
| eicar-com-txt, eicar-com-zip | downloaded-eicar | eicar-test-string (no FilesMagic rule exists) |

## 4. VM isolation: drift found and corrected (2026-11-03)

A read-only check found that the VM had drifted from its validated C9.2 state:
- network adapter 1 was set to NAT, with the cable connected;
- clipboard and drag-and-drop were both bidirectional;
- the Guest Additions ISO was attached.

**Correction (VirtualBox 7.2.20, VM powered off):**
- No snapshot was restored, and no disk or snapshot was changed.
- The settings were backed up first.
- Applied: `modifyvm --nic1 none --cable-connected1 off --clipboard-mode disabled
  --drag-and-drop disabled` and `storageattach --storagectl IDE --port 0 --device 0
  --medium emptydrive`.
- The before/after diff contains only those changes.

| Check | Result |
|---|---|
| Adapters 1-8 | `none` ✔ |
| Clipboard, drag and drop | `disabled` ✔ |
| Optical drive | `emptydrive` ✔ |
| USB (OHCI/EHCI/xHCI), audio, remote display, autostart | off ✔ |
| Shared folders | 0 ✔ |
| Settings after one boot and clean ACPI shutdown | unchanged ✔ |
| Guest-reported network interfaces: Guest Additions `/VirtualBox/GuestInfo/Net/Count` (TRANSRESET, written during this boot) | **0** ✔ |

**Still to confirm inside the guest**, which needs a login:
- `ip -br link` shows only `lo`;
- `ip route` and `ip -6 route` are empty.

`evaluation.benchmark` makes the same check itself and refuses to start if the VM has any usable
route. The strict-isolation preflight still applies. Because the VM has no network adapter, a
usable route cannot exist, but the in-guest check is the evidence for the record.

Consider taking a new snapshot ("isolation corrected 2026-11-03") once the in-guest check
passes. Guest Additions remain installed in the guest. With clipboard, drag-and-drop and shared
folders disabled on the host they have no data channel, but they are attack surface the C9.2
baseline may not have had.

## 5. Acquisition and transfer (outside the scanning VM)

1. **Acquire** on an online host that is not the VM:
   `python -m evaluation.acquire --out <cache> --dry-run`, review the plan, then run it without
   `--dry-run`. `--only` restricts acquisition to some ids. It writes the files and
   `provenance.json` (URL, SHA-256, size, source, retrieval time). The four Didier Stevens files
   were acquired this way on 2026-11-03.
2. **Prepare** the samples from the committed tree:
   `python -m evaluation.prepare_samples --out <samples> --acquired <cache>`. Generation is
   deterministic for a given Python and zlib build: the same commit and tools gave bit-identical
   samples twice, for all 13. A different zlib may compress differently, which is why the VM uses
   the transferred bytes pinned by the manifest rather than regenerating them.
3. **Build the transfer ISO** from the pushed commit:
   `powershell -NoProfile -ExecutionPolicy Bypass -File evaluation\vm\build_transfer_iso.ps1
   -Samples <samples> -Acquired <cache> -OutDir <dir>`. It refuses uncommitted or unpushed code,
   EICAR material, unexpected tool directories, and samples that don't match their manifest. The
   UDF image holds:
   - the commit (`filesmagic.bundle`, `source-<sha>.tar`, `COMMIT.txt`);
   - the samples and manifest;
   - the tools with their provenance;
   - `install_from_iso.sh`, taken from the commit itself;
   - `SHA256SUMS`.
4. **Transfer:** attach the ISO to the powered-off VM, boot it, mount the ISO read-only, run
   `install_from_iso.sh` from it, unmount, shut down, and detach the ISO. The optical drive is then
   back in its validated empty state.
5. **EICAR (not yet):** the Windows host's real-time anti-malware will quarantine it in transit.
   Choose with the supervisor:
   - an encrypted container opened only inside the VM;
   - a supervisor-approved, single-folder Defender exclusion;
   - or running without EICAR.

## 6. Reproduction inside the Ubuntu VM (offline)

The VM confines its evaluation interpreter with the enforcing AppArmor profile
`filesmagic-eval-python`. That profile allows **reading** only:
- `~/filesmagic-security-engine`;
- `~/fm-eval/samples/**`;
- `/tmp`.

It allows **writing** only to `~/fm-eval/results/**` and `/tmp`. The installer puts everything in
those places. Don't move it elsewhere, and don't relax the profile.

```bash
C=<commit>; S=~/fm-eval/samples/eicar-didier-${C:0:7}
cd ~/filesmagic-security-engine && git rev-parse HEAD && git status --porcelain   # = $C, no output
export SECURITY_ENGINE_REQUIRE_ISOLATION=1
/opt/filesmagic/venv/bin/python -m evaluation.benchmark --manifest $S/manifest.csv --samples-root $S \
    --acquired $S-tools --expect-commit $C --trials 20 --out ~/fm-eval/results/eicar-didier-${C:0:7}-run1
```

The benchmark aborts (exit code 3, `run_status.json`) unless:
- the VM has no usable network route;
- the expected commit is checked out with a clean tree;
- the installed packages match `requirements.txt`;
- the strict-isolation preflight passes.

Isolation is re-verified on every scan. Outputs:
- `report.md` (the short research report);
- `results.json`, `per_sample.csv`, `features.csv` (feature × method), `timings.csv` (per trial:
  harness wall-clock, worker total, worker overhead, each scanner);
- `summary.json`.

## 7. Three demonstrations for Friday, November 6

All three come from the same report. Until the VM run exists, a functional run on this machine's
local samples (marked NOT A VALID RESEARCH RUN) gives the same tables.

1. **The obfuscation blind spot.** Compare `pdf-js-openaction-local` with
   `pdf-js-obfuscated-local`.
   - YARA-X flags only the plain one: `/J#61vaScript` defeats its byte patterns.
   - PDF Analysis flags both, because pypdf decodes the names.
   - The custom scanner's C1 is the only method that reports the obfuscation itself, with its
     location.
   - PDFiD's `hexcodecount` gives an independent confirmation. For the object-stream variant,
     PDFiD's raw-byte view is expected to see only `/ObjStm`; confirm this in the VM run.
2. **Declared versus actual, in Office.**
   - `docx-clean-local` comes out SAFE.
   - In `docx-external-template-local`, Office Analysis flags the auto-loading external template.
   - In `docx-macro-declaration-mismatch-local`, three methods give three different explanations:
     YARA-X matches the `vbaProject.bin` name, Office Analysis finds the VBA storage, and the
     custom scanner's C4 reports that the declared macro-free type contradicts the content.
3. **Honest negatives and cost.**
   - EICAR is recorded exactly as the engine reports it. FilesMagic is a structural document
     analyser, not an anti-virus signature engine, and that is the correct, reported result.
   - Then the timing table: each scanner takes milliseconds, while worker start-up and isolation
     set-up account for almost all of the latency.
