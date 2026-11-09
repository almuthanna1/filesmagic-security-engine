# Emotet pilot: outstanding-requirements checklist

| | |
|---|---|
| Status | **Blocked on the items below. Do not acquire, transfer, extract, open or scan the sample until every one is met.** |
| Sample | Emotet .doc `e50c941c…a6a1ff` (pre-registration: [malware-eval-e50c941c-preregistration.md](malware-eval-e50c941c-preregistration.md)) |
| Tool | `evaluation/single_sample.py` at validated commit `47fb891` (branch `research/offline-single-sample`); inert validation [passed](evidence/single-sample-inert-15126e8/README.md) |

Technically ready (done): the tool, the real-oletools extraction path (benign macro fixture), CI
green (all three jobs), the 114-result control, the inert single-sample tests, the SHA-256 mismatch
guard, and the `~/fm-eval/samples/` input path under AppArmor. **Not** ready: authorization,
provenance, containment and handling below.

## A. Institutional authorization

- [ ] **Dr. Haque — written approval** recorded in [handling procedure §12](malware-sample-handling-procedure.md), naming **this sample**, the **personal laptop**, and VM **`FilesMagic-securityLAB`**. (Reported verbally; the record is still blank.)
- [ ] **NIU IT security / research compliance — written determination** that live document malware may be handled **on this specific personally-owned laptop and VM**, with any conditions (device encryption, no NIU network/data on the device, retention, incident reporting). The office is not yet identified; identify it with Dr. Haque. **Dr. Haque's approval does not substitute for this.**
- [ ] **IRB** confirmed not applicable (no human subjects/data) — confirm with Dr. Haque in writing.
- [ ] **Source terms** accepted by the researcher: MalwareBazaar account + Auth-Key; VirusTotal lookup terms.

## B. Sample provenance (label basis)

- [ ] **MalwareBazaar record** read by the researcher: family signature, tags, vendor intelligence, `first_seen`.
- [ ] **VirusTotal hash lookup** (never upload): detection count and vendor labels.
- [ ] **Pre-registration §1.1 vendor table filled in**; label basis met (family attribution **and** ≥5 vendor detections or a published analysis). Independent corroboration already on file: Triage reports from 2021-01-13 (score 10, macro), matching SHA-1/MD5/size.
- [ ] Record any vendor disagreements.

## C. Containment changes (each a separate approval; isolation settings otherwise unchanged)

Host (Windows):
- [ ] BitLocker **on** for the volume holding the VM, the ISO and `C:\fm-samples\` (verified, recorded).
- [ ] VirtualBox at the current maintenance release; Defender on, no new exclusions.
- [ ] A dedicated **non-synced** sample folder `C:\fm-samples\` (outside OneDrive).

VM (`FilesMagic-securityLAB`) — observed state that must change (from the inert run, read-only):
- [ ] **Tracker indexing disabled and verified** (`tracker3 daemon --pause` / Search off). *Currently running with file monitors on.*
- [ ] **Thumbnailers off** (`org.gnome.desktop.thumbnailers disable-all true`). *Currently local thumbnails enabled; `evince.thumbnailer` installed.*
- [ ] **Automount off** (`automount` and `automount-open` false). *Currently both on — a disc opens a Files window automatically.*
- [ ] New snapshot **"Pre-sample baseline"** (existing snapshots untouched), reverted after the session.
- [ ] A **`noexec`** sample mount; samples `chmod a-x`. (The single `sudo mount` is run by the researcher.)
- [ ] Optional: study-only AppArmor profile without the test-only rules, re-validated on the inert sets first.
- [ ] Network adapters remain **unattached**; settings diff empty before and after.

## D. Sample handling and transfer (none of this exists yet)

- [ ] **Acquire** the AES-encrypted ZIP with a command-line client into `C:\fm-samples\` (not a browser); verify the archive hash; **never decrypt on the host**; custody-log entry.
- [ ] **Sample-medium builder**: a *separate* ISO builder that packages only the encrypted archive, the manifest, `SHA256SUMS`, and a **hash-pinned AES-capable extractor** (e.g. 7-Zip for Linux — itself a new download needing its own provenance check and approval). It must refuse any decrypted Office/PDF file and is never placed in the repository or OneDrive. *(The existing `build_transfer_iso.ps1` is source-only and refuses EICAR; it is not for samples.)*
- [ ] **Session** (one VM session, after approvals): attach the sample ISO → copy archive → unmount/eject → extract to the `noexec` dir → verify SHA-256 → inert control 114/114 → `single_sample` on the Emotet doc (5 trials) → inert control 114/114 → `copyfrom` the metadata-only results → power off → revert the baseline → `emptydrive` → settings diff → delete host archive + ISO → close the custody log.
- [ ] **Recording**: metadata only (verdicts, rule IDs, scanner status, isolation, timings), findings redacted; **no sample bytes, no URLs/IOCs, no extracted macro text** in the repo (the public repo). The report is already redacted and JavaScript-free by construction.
- [ ] **Retention/destruction** per the handling procedure, confirmed by Dr. Haque.

## E. Run command (reference, once A–D are satisfied)

The pilot runs at commit `47fb891` from the sample's committed expectations:

```
SECURITY_ENGINE_REQUIRE_ISOLATION=1 /opt/filesmagic/venv/bin/python -B -m evaluation.single_sample \
  --sample ~/fm-eval/samples/malicious/m5-emotet-e50c941c.bin \
  --sha256 e50c941c576a54fb30415ca63016572e9104d7be02cf3a1f220e72e6aec6a1ff \
  --expectations evaluation/expectations/m5-emotet-e50c941c.json \
  --expect-commit 47fb891502cd68db62e7cb43dd05e327ffaab021 --trials 5 \
  --out ~/fm-eval/results/single-m5-emotet-e50c941c-47fb891
```
