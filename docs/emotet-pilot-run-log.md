# Emotet pilot — run log, approvals, environment and custody

| | |
|---|---|
| Sample | Emotet .doc `e50c941c…a6a1ff` |
| Tool | `evaluation/single_sample.py` at validated commit `47fb891` (branch `research/offline-single-sample`) |
| Pre-registration | [malware-eval-e50c941c-preregistration.md](malware-eval-e50c941c-preregistration.md) (predictions fixed; **not edited by this run**) |
| Checklist | [emotet-pilot-outstanding-requirements.md](emotet-pilot-outstanding-requirements.md) |
| This log records | approvals as supplied by the researcher, environment checks, the label basis, and the custody log. **No authorization evidence is fabricated: blank fields stay blank until the researcher supplies them.** |

## 1. Approvals (as reported by the researcher)

On **2026-11-09** the researcher (Almuthanna Shihab) reported that the required approvals for the
genuine-malware evaluation were received, **including use of the personal laptop and the
`FilesMagic-securityLAB` VM**. The specifics below are to be completed by the researcher from the
written approvals; they are **not** filled in by the assistant.

| Approval | Approver (name/role) | Date | Reference / where recorded | Conditions |
|---|---|---|---|---|
| Supervisor (Dr. Nur Imtiazul Haque) | | | | |
| NIU IT security / research compliance (this personal laptop + VM) | | | | |
| IRB not applicable (confirmed) | | | | |
| Source terms (MalwareBazaar Auth-Key, VirusTotal lookup) | | | | |

Handling procedure §12 should carry the countersigned record; this table is a convenience copy.

**Researcher's decision (2026-11-10).** The researcher states that **Dr. Haque has authorized the
research**, performed on the personal laptop in the isolated `FilesMagic-securityLAB` VM, and
directs that the unverified NIU IT security and IRB determinations **not be treated as blockers**.
The supervisor's written approval details and any NIU IT / IRB determinations were **not supplied**
and are not recorded as obtained; the table above stays blank until they are. The experiment
proceeds on the researcher's decision under the supervisor's authorization.

## 2. Environment checks (2026-11-09, assistant-verified)

| Item | Result | OK? |
|---|---|---|
| VirtualBox | 7.2.20 r175154 | note: confirm it is the current maintenance release |
| Windows Defender | real-time protection **on**, AV/antispyware enabled, Normal mode | yes |
| Defender exclusions | **none** (ExclusionPath/Extension/Process all empty, confirmed elevated by the researcher) | yes |
| **BitLocker on `C:`** | **Protection On**, XTS-AES 128, 100% (Used-Space-Only), key protectors TPM + Numerical Password (confirmed elevated by the researcher) | **yes** |
| VM `FilesMagic-securityLAB` | powered off; IDE 0-0 emptydrive; NICs none; clipboard/drag-drop disabled; USB/EHCI/XHCI off; VRDE off; 6 snapshots intact (current "C11 - Offline Research Evaluation Ready") | yes |
| Non-synced storage | `C:\tmp` is non-synced (not under OneDrive); `C:\fm-samples\` does not exist yet; the VM, snapshots and ISOs all live on `C:` | partial |
| Frozen engine | at HEAD `47fb891` `app/` tree = `c50b66c1…` (frozen); `requirements.txt` = `5089f11d…`; unchanged vs tag | yes |
| Expectations | `evaluation/expectations/m5-emotet-e50c941c.json` committed; `sample_sha256` = the target; both engines pre-registered **MALICIOUS** | yes |

The VM, its snapshots and the ISOs are on `C:`, which is BitLocker-encrypted (above); `C:\fm-samples\`
will be on `C:` too. The encryption-at-rest containment control is met.

### 2a. Containment preparation (2026-11-09, assistant-applied in the VM)

Applied in the guest as the ordinary user (via the session bus), verified, logs in the VM at
`~/fm-eval/results/containment-47fb891/` (exported with the session evidence):

| Control | State | Verified |
|---|---|---|
| Automount / automount-open / autorun | `automount=false`, `automount-open=false`, `autorun-never=true` | yes |
| Thumbnailers | `org.gnome.desktop.thumbnailers disable-all=true`; Nautilus image thumbnails `never` | yes |
| Tracker indexing | index dirs `[]`, monitors `false`; all tracker user services **masked** (→ 0 miners after reboot) | yes |
| Sample mount point | `~/fm-eval/samples/malicious` created, `0700` (empty) | yes |
| Guest isolation checks | `guest_checks.sh` **all PASS, 0 STOP** (interfaces lo-only, no routes, no shared FS, interpreter root-owned, AppArmor `6a94078…` enforce) | yes |
| **Pre-sample baseline snapshot** | **"Pre-sample baseline - containment configured 2026-11-09"** (UUID `fa08a4db…`), taken powered-off; the six existing snapshots preserved; now the current snapshot | yes |
| VM isolation after prep | powered off; IDE 0-0 emptydrive; NICs none; clipboard/drag-drop/USB/VRDE off | yes |

The **noexec sample mount** is a session-time one-command step the researcher runs after revert +
login (it is a volatile tmpfs, not captured in the powered-off snapshot):

```
sudo mount -t tmpfs -o noexec,nosuid,nodev,mode=0700,uid=$(id -u),gid=$(id -g),size=64m tmpfs ~/fm-eval/samples/malicious
# (uid/gid needed: without them the root-owned 0700 mount is not writable by the user)
# validate: a file copied in cannot be executed (Permission denied); unmount with
sudo umount ~/fm-eval/samples/malicious
```

### 2b. AES extractor (2026-11-09, assistant-verified on the host)

| Item | Result |
|---|---|
| File | `C:\fm-samples\7z2606-linux-x64.tar.xz`, 1,575,552 bytes, 7-Zip **26.06** (2026-11-06), downloaded by the researcher |
| SHA-256 | `2b539cf067b2ad48e1baa5093dbaa8818b73542d1222a0ffde9dc5f2922ea62e` |
| Source | **Matches the official release byte for byte**: 7-zip.org's download page links its releases to `github.com/ip7z/7zip`; release `26.06` (published 2026-11-07T11:45:33Z by `ip7z`) lists this asset at the same size with digest `sha256:2b539cf0…a62e`. The file's Zone.Identifier records `HostUrl=https://chatgpt.com/` (the channel it came through), so provenance rests on the hash match, not on the download path. |
| Contents | 7zz, 7zzs, readme, History, License, MANUAL/; no absolute or `..` paths, no links |
| **Binary to use: `7zzs`** (static) | `0b58a64e71ebdf53751cd954cad1cc552c6a11ef51336bee6acafbdc54c28c1f`, 3,759,224 bytes; ELF64 x86-64 EXEC, **no PT_INTERP, no PT_DYNAMIC** (statically linked, so it does not depend on the VM's libraries). `7zz` (`f94066e9…83b5`) is the dynamically linked build and is not used. |
| Benign AES test archive | `fm-aes-test.zip`, built by [`evaluation/vm/aes_test_zip.py`](../evaluation/vm/aes_test_zip.py) (independent of 7-Zip; password `infected`), **byte-identical on rebuild**: SHA-256 `732390512af7908b57c080c6c6e2b52e741d7b2aeb1b6a584a15e4d4b4a17697`, 531 bytes. Entries: `aes-test/ae1-stored.txt` (WinZip AE-1, AES-256, stored) `a69a6d76…088d`; `aes-test/ae2-deflate.txt` (AE-2, AES-256, deflate) `c26c0988…8332`. Plain text only. |
| Host decode check (same 7-Zip 26.06 release, Windows build) | lists both entries as `AES-256 Store` / `AES-256 Deflate`; extraction exit 0 and **both entry hashes match**; wrong password → exit 2. The archive is a valid WinZip-AES file. |
| **In-VM check with `7zzs`** | **PASS (2026-11-10 04:27Z)**, from the baseline, reverted after ([evidence](evidence/aes-extractor-7zzs-2606/README.md)): `7zzs` hash matches the pin in the guest; both entries decrypted and **match their SHA-256**; wrong password → exit 2 (but **leaves 0-byte placeholders**, so the session trusts the exit code and the document hash, not file existence); a file in the `noexec` mount cannot execute; `guest_checks.sh` all PASS. |

**Host note.** `C:\fm-samples\` also holds a full Windows 7-Zip installation (`7z.exe`, `7z.dll`,
`7zFM.exe`, `Uninstall.exe`, …), from the hash-verified official `7z2606-x64.exe`. It was used here
only to decode the benign test archive. It must **never** be used on the sample archive (the sample
is never decrypted on the host), and it should be uninstalled before the archive is downloaded.

## 3. Independent label basis (metadata only; no sample handled)

Automated lookups are blocked to non-interactive clients (VirtualTotal HTTP 429; MalwareBazaar
anti-bot). Independent corroboration already on file:

- **Tria.ge** — four sandbox reports (first 2021-01-13), all **score 10/10**, tag **macro**; matching
  **SHA-1 `59721461…`**, **MD5 `0992c8eb…`**, size ~157 KB; submitter file names `emotet_e2_…`/`emotet_doc2`.
- Documented E2 (epoch 2) behaviour: Document_Open VBA → WMI process creation → PowerShell downloader
  (family background, not a per-file vendor verdict).

### 3a. MalwareBazaar record (authenticated API `get_info`, 2026-11-10 04:43Z)

Read from `C:\fm-samples\e50c941c-info.json` (17,974 bytes, SHA-256 `0a7761c2…1b15`; host only, not
committed: it carries IOCs). Only labels and verdicts are reproduced; URLs, hosts and the malware
configuration are withheld.

| Field | MalwareBazaar | Pre-registration (§1) | Match |
|---|---|---|---|
| SHA-256 | `e50c941c…a6a1ff` | same | **yes** |
| SHA-1 / MD5 | `59721461…e6b9` / `0992c8eb…d664` | same (Triage) | **yes** |
| Size | **160,779 bytes** | "about 157 KB" (exact count unknown) | yes (160,779 B = 157.0 KiB); now exact |
| Format | MIME `application/msword`; OLE analysis (`oleid`, `olevba`) present; tag `doc`; DocGuard "Legacy Word File with Macro"; submitted name ends `._doc` | legacy OLE2 `.doc`, macro | **yes** |
| `file_type` label | **`docx`** | `.doc` | **discrepancy (naming only)**, see below |
| Family | signature **`Heodo`** (= Emotet); tags `emotet`, `epoch2`, `Heodo`, `doc`; comment "Emotet epoch2 doc" | Emotet (Heodo), E2 | **yes** |
| First seen | 2021-01-13 07:00:42 UTC, reporter `Cryptolaemus1` | Triage first analysed 2021-01-13 06:57 UTC | yes |
| Archive password | `archive_pw` null → the API's documented default `infected` | — | — |

**Vendor intelligence (MalwareBazaar):**

| Vendor | Verdict / label |
|---|---|
| ReversingLabs | MALICIOUS, `Document-Word.Trojan.Heuristic`, **16 / 44 scanners** (36.36 %) |
| ANY.RUN | Malicious activity; tags macros, macros-on-open, emotet-doc, emotet |
| CERT-PL MWDB | emotet |
| YOROI YOMI | Emotet, score 1.00 |
| InQuest | MALICIOUS |
| DocGuard | Malicious, alert level 9.0 |
| vxCube | malware, maliciousness 100 |
| Triage | score 10, tag macro, 14 behavioural signatures, no family field |
| Spamhaus HBL | suspicious |
| ClamAV (MalwareBazaar `intelligence`) | 3 signatures, including `Doc.Dropper.EmotetRed1220-9816007-0` |

### 3b. VirusTotal

**Unavailable**: not read (HTTP 429 to an automated client; no researcher lookup supplied). Recorded
as unavailable, not estimated.

### 3c. Label decision (pre-registered rule, plan §3)

`MALICIOUS` requires a MalwareBazaar listing with a family attribution **and** ≥5 vendor detections
or a published analysis. **Met**: family `Heodo`/Emotet; ≥5 independent vendor detections (ReversingLabs
16 scanners, ANY.RUN, CERT-PL, YOROI, InQuest, DocGuard, vxCube, ClamAV); and four public Triage
analyses (score 10). The label `MALICIOUS` and the pre-registered predictions are **unchanged**.
Disagreements: Spamhaus HBL says only "suspicious"; Triage and ANY.RUN name no family; ReversingLabs'
match rate is 36 %.

**Discrepancy: `.docx` name.** MalwareBazaar's `file_type` is `docx`, so the archive entry is named
`<sha256>.docx`, while every content indicator says legacy OLE2 Word (MIME, OLE analysis, DocGuard,
the `doc` tag, the `._doc` submission name). The scan does not depend on the name: the worker
receives only the bytes (`worker.run(data, cmd)`), and the file is renamed `m5-emotet-e50c941c.bin`
on extraction (§2a run command). Identity rests on the SHA-256 checked before scanning. The actual
container format will be recorded from the scanners' output, not assumed.

## 4. Custody log (one row per movement; filled during the session)

| Time (UTC) | Action | Location | SHA-256 (encrypted archive / document) | By |
|---|---|---|---|---|
| 2026-11-10 04:43:06 | download encrypted ZIP (MalwareBazaar API `get_file`, researcher's Auth-Key, PowerShell `Invoke-WebRequest`); never opened or decrypted on Windows | `C:\fm-samples\e50c941c.zip` (not synced, BitLocker) | archive `f6c9a7cc614166d5d12798b00d9636939faf566ec66fbb656800de3720c90fbb`, 87,183 B | researcher |
| 2026-11-10 | verify archive without decrypting: 1 entry `e50c941c…a6a1ff.docx`, AES-128 (AE-2, deflate), 160,779 B uncompressed, CRC `67269544`; Defender on, no detection | host | archive hash re-computed: match | assistant |
| 2026-11-10 ~04:48 | build sample ISO (encrypted archive + pinned `7zzs` + AES-128 benign test + `SHA256SUMS`; builder refuses any other file and any unencrypted entry) | `C:\fm-samples\fm-sample-e50c941c.iso` | ISO `1c6036699666838955af8476f69cd89b36fddbf2ff3d329d6126de1a5ce8ac9b`; archive inside `f6c9a7cc…0fbb` | assistant |
| 2026-11-10 | attach ISO (VM off at baseline; only `IDE-0-0` changed); boot | VM | — | assistant |
| 2026-11-10 16:19:00Z | disc verified in the guest (whole disc = ISO); archive extracted **directly from the disc** into the `noexec` tmpfs (never copied to the VM disk); disc unmounted | VM `noexec` tmpfs | document **`e50c941c…a6a1ff`, 160,779 B: match** | assistant |
| 2026-11-10 16:19:18–16:19:27Z | static scan, 5 trials × 2 engines (**both MALICIOUS**, PASS) | VM | sample unchanged after the scan | assistant |
| 2026-11-10 16:20:46Z | export sanitized metadata (`copyfrom`); ACPI power off; `restorecurrent` "Pre-sample baseline" (session disk discarded; tmpfs gone with power-off) | VM → `docs/evidence/single-sample-emotet-e50c941c-47fb891/` | export hashes verified | assistant |
| 2026-11-10 | delete host archive, ISO (+ `.sha256`), staging copy and metadata JSON | `C:\fm-samples\` | — | **researcher** (assistant's sandbox refuses deletion there) |
| 2026-11-10 | **verify cleanup**: `C:\fm-samples\` holds only the benign 7-Zip tarball; no file named `*e50c941c*`/`fm-sample*` and no file of the archive's (87,183 B) or document's (160,779 B) size in every location the archive or its exports touched (`C:\fm-samples`, the session scratchpad, `C:\tmp\fm-aes-test-iso`, `C:\tmp\fm-emotet-export`, `C:\tmp` to depth 2, Downloads, the VM folder, the research worktree outside `docs/evidence`); the document was never present on the host (only inside the VM tmpfs, gone at power-off and discarded with the baseline restore). The VM's media registry still lists the deleted ISO path (inaccessible; not attached to the drive or any snapshot). **Custody closed.** | host | — | assistant |

## 4a. Result (2026-11-10)

**Both engines: MALICIOUS** (5/5 trials each, deterministic, every applicable scanner completed,
strict isolation complete, 3 routine AppArmor denials, none on the sample). Pre-registered outcome
**PASS**; 28/30 predictions held — `OFFICE_MACRO_OBFUSCATION` (P1) was predicted but absent in
both engines. Details: [evidence README](evidence/single-sample-emotet-e50c941c-47fb891/README.md).

## 5. Status of the prerequisites

| # | Prerequisite | Status |
|---|---|---|
| 1 | BitLocker on `C:` | **done** (§2) |
| 2 | Guest Control credential recreated | **done** |
| 3 | Containment applied + revalidated + baseline snapshot | **done** (§2a) |
| 4 | Approval specifics (§1) recorded | **open — researcher** |
| 5 | Label basis (§3) completed | **done** (§3c): MalwareBazaar family + ≥5 vendors + Triage; VirusTotal unavailable |
| 6 | `noexec` sample mount validated | **done** (2026-11-10, [evidence](evidence/aes-extractor-7zzs-2606/README.md)): options `noexec,nosuid,nodev`, exec refused; the researcher re-runs the one `sudo mount` (§2a) at the session's start |
| 7 | Offline **AES** extractor in the VM | **done** (§2b): official 7-Zip 26.06, static `7zzs` pinned `0b58a64e…8c1f`, decrypts the benign AES-256 test archive in the VM |

**Extractor (7).** MalwareBazaar archives use **AES** (password "infected" by default; confirm on the
sample's own page). The VM has only `unzip` (no AES), so the sample ISO carries the pinned `7zzs`
(the tested combination). In the VM: copy `7zzs` to `~/fm-eval/bin/` (exec-allowed) and check its
SHA-256 — **stop if it differs**. The format and the mount were validated on 2026-11-10 (§2b), so
the session does not repeat the test archive.

Only when 4–7 hold does the session proceed: download the encrypted archive (host) → build the
sample ISO (encrypted archive + manifest + `SHA256SUMS` + pinned `7zz`) → attach, mount, copy in →
extract into the `noexec` mount → **verify the document SHA-256 = `e50c941c…a6a1ff`** → inert control
→ `single_sample` (5 trials) at commit `47fb891` → export sanitized metadata → power off → revert
"Pre-sample baseline" → delete host archive + ISO → close this log. **Live malware never goes to
GitHub, cloud storage, Render/Vercel or the public Security Lab.**
