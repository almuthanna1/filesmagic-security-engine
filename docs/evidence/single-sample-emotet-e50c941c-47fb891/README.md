# First genuine-malware evaluation: Emotet `e50c941c…` at `47fb891` (2026-11-10): PASS

**Both frozen engines classify the genuine Emotet (Heodo, epoch 2) Word document as MALICIOUS**,
in all 5 trials each, deterministically, with every applicable scanner completed and strict
isolation complete. Static analysis only: the document was never opened in an Office application,
no macro was executed, and the VM stayed offline. Pre-registration:
[malware-eval-e50c941c-preregistration.md](../../malware-eval-e50c941c-preregistration.md) (not
edited; `preregistration_sha256` `9888d903…fc5d` in `results.json`). Provenance, custody and
approvals: [emotet-pilot-run-log.md](../../emotet-pilot-run-log.md).

**Only sanitized metadata is here**: no sample bytes, no macro text, no URLs/IOCs (the redactor
withheld one 131-character finding tail, kept as length + hash). The only address-like string in
these files is `192.0.2.1`, the documentation address the isolation check probes.

## Result

| | Reference | Unified |
|---|---|---|
| **Verdict (5/5 trials)** | **MALICIOUS** | **MALICIOUS** |
| Deterministic | yes | yes |
| Scanners completed | `yara-x`, `office` | `yara-x`, `office`, `yara-x-engine`, `vba-chains` |
| Not applicable | `pdf`, `custom` | `pdf`, `custom`, `pdf-chains`, `ooxml-links`, `word-fields` |
| Failed scanners | none | none |
| `isolation_missing` | none | none |
| Median / max wall time per scan | 506.3 / 798.5 ms | 537.6 / 612.9 ms |
| `office` scanner median | 40.7 ms | 24.6 ms |
| `vba-chains` median | — | 70.6 ms |

**Triggered rules (identical in both engines):**

| Rule | Severity | Description (as reported) |
|---|---|---|
| `office:OFFICE_MACRO_AUTOEXEC_EXECUTION` | **HIGH** | Macro code runs automatically on open and can execute commands or download files. |
| `office:OFFICE_MACRO_AUTOEXEC` | MEDIUM | Macro code runs automatically via: Document_open. |
| `office:OFFICE_MACRO_DANGEROUS_CAPABILITY` | MEDIUM | May execute file or a system command through WMI. |
| `yara-x:OLE_Office_VBA_Macros` | MEDIUM | Legacy Office (OLE) document contains a VBA macro project. |
| `office:OFFICE_MACROS_PRESENT` | LOW | Document contains a VBA/XLM macro project. |
| `office:OFFICE_MACRO_SUSPICIOUS_KEYWORDS` | LOW | May create an OLE object. |

Unified also reports `vba-chains:ENGINE_VBA_CALL_PATH_UNDETERMINED` (INFO) and
`vba-chains:ENGINE_CORRELATION` (INFO: the Office scanner's HIGH was **kept** because the macro call
path could not be determined). The verdict is driven by the HIGH finding in both engines.

## Against the pre-registration

Acceptance criteria (§4) for **PASS**: both engines MALICIOUS; `OFFICE_MACRO_AUTOEXEC` and
`OFFICE_MACRO_DANGEROUS_CAPABILITY` present; every applicable scanner completed; strict isolation
complete on all 10 results; identical across the 5 trials. **All met → PASS** (tool outcome PASS,
`defects` empty, exit 0).

**28 of 30 recorded predictions held. The 2 that did not are one prediction in both engines:
`office:OFFICE_MACRO_OBFUSCATION:LOW` (part of P1) was predicted but is absent.** olevba did not
flag obfuscation for this file. It is not an acceptance criterion, so the outcome stays PASS, but
P1 as written (all six office findings) **did not fully hold**. Recorded as observed; no rule or
prediction was changed.

| # | Prediction | Held? |
|---|---|---|
| P1 | `office` completes with MACROS_PRESENT, AUTOEXEC (Document_Open), DANGEROUS_CAPABILITY (WMI), SUSPICIOUS_KEYWORDS, OBFUSCATION, AUTOEXEC_EXECUTION HIGH | **partly**: all except OBFUSCATION |
| P2 | `yara-x` `OLE_Office_VBA_Macros` MEDIUM | yes |
| P3 | `pdf`/`custom` not applicable; no scanner failure | yes |
| P4 | Reference MALICIOUS | yes |
| P5 | `vba-chains` `ENGINE_VBA_CALL_PATH_UNDETERMINED` INFO (medium confidence) | yes (the main prediction, not the alternative) |
| P6 | Unified MALICIOUS; correlation keeps the HIGH | yes |
| P7 | Deterministic over 5 trials; strict isolation complete | yes |
| P8 | Latency well below 30 s; unified slower than reference by the `vba-chains` re-parse | below 30 s: yes. Unified median 537.6 vs 506.3 ms: yes; per-scan maximum is lower for unified (612.9 vs 798.5 ms, one slow reference trial) |

## Containment and integrity (session logs)

| Step | Result |
|---|---|
| VM before attach | powered off at "Pre-sample baseline" (`fa08a4db…`); attach changed only `IDE-0-0` (`host/vm-settings-attach-diff.txt`) |
| `guest_checks.sh` before and after | all PASS, `RESULT all controls present` (lo only, no routes, no shared FS, AppArmor `6a94078…` enforce) |
| Frozen engine in the VM | HEAD `47fb891`, `app/` `c50b66c1…`, `requirements.txt` `5089f11d…`, clean tree |
| Sample disc `1c603669…ac9b` | `SHA256SUMS` 3/3; whole `/dev/sr0` = host ISO; unmounted before scanning |
| `noexec` tmpfs | `noexec,nosuid,nodev`, empty before extraction |
| Extractor | `7zzs` pinned `0b58a64e…`; AES-128 benign test decrypted first |
| **Sample** | extracted from the AES-128 archive into the tmpfs; **SHA-256 = `e50c941c…a6a1ff`, 160,779 bytes**; mode 0400; magic `D0 CF 11 E0 A1 B1 1A E1` (OLE2, confirming the `.docx` label was naming only); unchanged after the scan |
| AppArmor denials (session) | **3**, all `filesmagic-eval-python`: `uname` exec (2), `git` index.lock (1) — the same kinds every inert run shows; **none on the sample path, no other exec** (`session/apparmor-denials.txt`, `apparmor-recount.log`) |
| Office/Wine | none installed, none running (`session/verify-flags.log`) |
| Shutdown + revert | ACPI 5 s; `restorecurrent`; settings vs pre-attach differ only in state time, the fresh differencing disk and runtime Guest-Additions keys; `IDE-0-0` emptydrive, NICs `none`, 7 snapshots (`host/`) |

### Two measurement errors in the session script, corrected

1. Phase B printed **"FAIL office/wine process present"**: `pgrep -f` matched the script's own
   shell (PID 4419), whose command line contained the pattern. Re-checked by executable name: no
   such process, none installed.
2. Phase B printed **"AppArmor denials since scan start: 0"**: the VM's journal reads `--since` in
   local time (America/Chicago) and the script passed UTC, so the window was in the future.
   Re-counted with an epoch timestamp: 3 (above).

`session/session-SHA256SUMS` was written while `apparmor-recount.log` was still being written,
so that one entry does not verify; the final file hashes identically in the guest and on the host
(`3a330dc1…4a25`). All other session files and `single/SHA256SUMS` verify.
