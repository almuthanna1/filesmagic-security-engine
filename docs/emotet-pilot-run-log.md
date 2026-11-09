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
sudo mount -t tmpfs -o noexec,nosuid,nodev,mode=0700,size=64m tmpfs ~/fm-eval/samples/malicious
# validate: a file copied in cannot be executed (Permission denied); unmount with
sudo umount ~/fm-eval/samples/malicious
```

## 3. Independent label basis (metadata only; no sample handled)

Automated lookups are blocked to non-interactive clients (VirtualTotal HTTP 429; MalwareBazaar
anti-bot). Independent corroboration already on file:

- **Tria.ge** — four sandbox reports (first 2021-01-13), all **score 10/10**, tag **macro**; matching
  **SHA-1 `59721461…`**, **MD5 `0992c8eb…`**, size ~157 KB; submitter file names `emotet_e2_…`/`emotet_doc2`.
- Documented E2 (epoch 2) behaviour: Document_Open VBA → WMI process creation → PowerShell downloader
  (family background, not a per-file vendor verdict).

To meet the plan's label basis (family attribution **and** ≥5 vendor detections or a published
analysis), the researcher supplies, from authenticated access (numbers/labels only, **never upload
the file**):

| Source | Detections / total | Family labels | Date read |
|---|---|---|---|
| MalwareBazaar vendor intelligence | | | |
| VirusTotal hash lookup | | | |

## 4. Custody log (one row per movement; filled during the session)

| Time (UTC) | Action | Location | SHA-256 (encrypted archive / document) | By |
|---|---|---|---|---|
| | download encrypted ZIP | `C:\fm-samples\` | | |
| | build sample ISO | `C:\fm-samples\` | | |
| | attach ISO, copy archive into VM | VM tmpfs | | |
| | extract + verify document hash | VM `noexec` mount | `e50c941c…a6a1ff` | |
| | scan (5 trials × 2 engines) | VM | — | |
| | power off + revert "Pre-sample baseline" | VM | — | |
| | delete host archive + ISO | `C:\fm-samples\` | — | |

## 5. Status of the prerequisites

| # | Prerequisite | Status |
|---|---|---|
| 1 | BitLocker on `C:` | **done** (§2) |
| 2 | Guest Control credential recreated | **done** |
| 3 | Containment applied + revalidated + baseline snapshot | **done** (§2a) |
| 4 | Approval specifics (§1) recorded | **open — researcher** |
| 5 | Label basis (§3) completed | **open — researcher** (MalwareBazaar + VirusTotal counts) |
| 6 | `noexec` sample mount validated | **open — researcher** runs the one `sudo mount` (command in §2a) |
| 7 | Offline **AES** extractor in the VM | **open** — see below |

**Extractor (7).** MalwareBazaar archives use **AES** (password "infected" by default; confirm on the
sample's own page). The VM has only `unzip` (no AES) and no `7z`/`pyzipper`, so an AES-capable
extractor must be brought in on the sample medium: a **hash-pinned static `7zz`** from the official
7-Zip release (`7z<version>-linux-x64.tar.xz`, 7-zip.org), run from an exec-allowed dir
(`~/fm-eval/bin/`), extracting into the `noexec` sample mount. The researcher downloads it on the
host, records its SHA-256, and it is packaged on the sample ISO.

Only when 4–7 hold does the session proceed: download the encrypted archive (host) → build the
sample ISO (encrypted archive + manifest + `SHA256SUMS` + pinned `7zz`) → attach, mount, copy in →
extract into the `noexec` mount → **verify the document SHA-256 = `e50c941c…a6a1ff`** → inert control
→ `single_sample` (5 trials) at commit `47fb891` → export sanitized metadata → power off → revert
"Pre-sample baseline" → delete host archive + ISO → close this log. **Live malware never goes to
GitHub, cloud storage, Render/Vercel or the public Security Lab.**
