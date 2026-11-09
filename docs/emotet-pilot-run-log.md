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
| Defender exclusions | require admin to view — **researcher to confirm no exclusion covers the VM, the ISOs or `C:\fm-samples\`** | pending |
| **BitLocker on `C:`** | **appears NOT enabled** (`C:` has no associated BitLocker volume; admin needed to confirm) | **NO — blocker** |
| VM `FilesMagic-securityLAB` | powered off; IDE 0-0 emptydrive; NICs none; clipboard/drag-drop disabled; USB/EHCI/XHCI off; VRDE off; 6 snapshots intact (current "C11 - Offline Research Evaluation Ready") | yes |
| Non-synced storage | `C:\tmp` is non-synced (not under OneDrive); `C:\fm-samples\` does not exist yet; the VM, snapshots and ISOs all live on `C:` | partial |
| Frozen engine | at HEAD `47fb891` `app/` tree = `c50b66c1…` (frozen); `requirements.txt` = `5089f11d…`; unchanged vs tag | yes |
| Expectations | `evaluation/expectations/m5-emotet-e50c941c.json` committed; `sample_sha256` = the target; both engines pre-registered **MALICIOUS** | yes |

**The VM, its snapshots and the ISOs are on `C:`, which is not encrypted. `C:\fm-samples\` would be
on `C:` too. The approved containment control "BitLocker on" is therefore unmet.** Transfer of the
live sample must not proceed until this is resolved (see §5).

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

## 5. Blockers before the live sample may be transferred

1. **BitLocker** enabled and verified on the volume holding the VM, the ISOs and `C:\fm-samples\`
   (admin). Or the research storage moved to an already-encrypted volume.
2. **Guest Control credential** recreated at `%LOCALAPPDATA%\fm-gc\guest.pw` (deleted at the end of
   the previous session) — needed to apply the containment settings and revalidate guest checks.
3. **Containment changes applied and revalidated** in the VM (Tracker off, thumbnails off, automount
   off), the **"Pre-sample baseline"** snapshot taken, and the **`noexec`** sample mount established.
4. **Label basis** completed (§3) and **approval specifics** recorded (§1).
5. **Offline AES extractor** confirmed present in the VM (p7zip) or brought in on the sample medium.

Only when 1–5 hold does the session proceed: download → build sample ISO → transfer → verify
SHA-256 → inert control → `single_sample` (5 trials) → export sanitized metadata → power off →
revert → delete host copies → close this log.
