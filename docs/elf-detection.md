# Linux ELF detection (custom Unified Engine)

Narrowly scoped static ELF analysis for the custom engine. Unified-only: the reference engine and
the frozen `2d586f6` release are unchanged. No sample is executed; nothing here downloads
signatures or adds an antivirus service.

## Problem

A ~1.2 MB Linux ELF (`SHA-256 7f14bb23…0a7f06`) came back SUSPICIOUS in both engines, on the single
reference rule `Native_Executable` (`app/rules/filesmagic.yar`, MEDIUM) that fires on the ELF magic
alone. Neither engine looked inside the file, so any ELF could only ever be SUSPICIOUS. The gap: no
way to raise a defensible MALICIOUS verdict on strong static evidence, and no structural context.

## What was added

1. **Bounded parser — `app/engine/elf.py`** (standard library only). Reads the ELF header, program
   headers (segments), section headers, and the dynamic table's needed libraries, soname and
   interpreter. Every count, offset and length is bounded (`MAX_SEGMENTS`, `MAX_SECTIONS`,
   `MAX_DYNAMIC`, `MAX_NAME`) and kept inside the file. Anything malformed or over a limit raises
   `ElfScanError`. It is a reader, not a loader: no relocation, no execution, no decompression.

2. **Structural scanner — `app/engine/elf_scan.py`** (`elf-structure`). Reports what the parser
   found, all at **INFO/LOW**, so structure alone never exceeds SUSPICIOUS:
   - `ENGINE_ELF_STRUCTURE` (INFO) — bits, type, machine, interpreter, needed libraries.
   - `ENGINE_ELF_WRITABLE_EXECUTABLE_SEGMENT` (LOW) — a loadable W^X segment.
   - `ENGINE_ELF_ENTRY_OUTSIDE_CODE` (LOW) — entry point outside any executable section.
   - `ENGINE_ELF_NO_SECTION_HEADERS` / `ENGINE_ELF_STRIPPED` (INFO).
   A non-ELF returns "not handled"; an unparseable ELF raises, so the worker records a failed scan
   and the file can never come back SAFE on this scanner. `Native_Executable` still marks it SUSPICIOUS.

3. **Signatures — `app/engine/rules/elf.yar`** (engine YARA-X, `yara-x-engine`). HIGH is reserved
   for validated malicious evidence:
   - `ELF_UPX_Tampered_Header` (**MEDIUM**, suspicious only) — the UPX decompression stub is present
     but the `UPX!` header magic is absent. Malware does this to block `upx -d`, but so do commercial
     protectors, and a banner embedded as data looks the same. A modified packer header alone is
     therefore never MALICIOUS, whatever structural anomalies accompany it.
   No production rule is HIGH. The path a validated signature will use is exercised by a test-only
   rule (`tests/rules/elf_marker.yar`, an inert marker) that no production scanner loads: `tests/`
   is outside the rule directories and outside the production image, and tests enforce both.
   No rule for a real malware family ships yet: none has been validated against genuine samples.
   A test (`test_only_validated_rules_can_be_high`) fails if any other rule is given HIGH without
   being listed as validated in `correlate.ELF_SIGNATURE_RULES`.

4. **Correlation — `app/engine/correlate.py`**. When a validated ELF signature (HIGH) fires and the
   parser confirmed a genuine ELF (`elf-structure` completed), it replaces the generic
   `Native_Executable`, which is kept as a raw line in the `ENGINE_CORRELATION` audit trail, and the
   structural indicators are listed as corroboration. A HIGH is never suppressed: if the parser did
   not complete, both findings stand and the gap is recorded. `ELF_UPX_Tampered_Header` changes
   nothing: `Native_Executable` stands beside it and the audit note says it is suspicious only.

## Before and after (final)

| Input | Reference | Unified before | Unified after |
|---|---|---|---|
| Ordinary ELF; stripped; W^X; no sections; entry outside code | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS |
| Modified UPX header (alone, or with every structural anomaly) | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS (`ELF_UPX_Tampered_Header` MEDIUM added) |
| Normally UPX-packed (`UPX!` present) | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS |
| Inert marker fixture, production rules | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS (same findings as the file without it) |
| Inert marker fixture with the test-only rule loaded and listed as validated (tests only) | - | - | MALICIOUS |
| Malformed or truncated ELF | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS (`elf-structure` failed, never SAFE) |
| Real system binaries (Linux CI) | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS |
| The real sample `7f14bb23…` | SUSPICIOUS | SUSPICIOUS | SUSPICIOUS (expected; not rescanned, see below) |

## Verdict policy

- Generic executable status, a W^X segment, stripping, missing sections, entropy or ordinary
  syscalls → at most SUSPICIOUS (INFO/LOW). Unknown executables stay **SUSPICIOUS**, never SAFE.
- A modified packer header → SUSPICIOUS (MEDIUM), alone or with structural anomalies.
- **MALICIOUS requires a validated malicious signature** that the parser corroborates as a real
  ELF. Today no production rule qualifies, so no file becomes MALICIOUS through
  this module until a family signature is validated in the offline VM.
- A malformed ELF fails closed (failed scan + SUSPICIOUS via `Native_Executable`), never SAFE.

## The 7f14bb23… sample

No public source (VirusTotal-indexed or otherwise) records this hash, so no family attribution or
detection evidence could be established independently, by hash alone. The sample was **not**
downloaded or executed. Its malicious behaviour has not been independently established, so it
**remains SUSPICIOUS**;
forcing MALICIOUS is not defensible. Confirming any verdict on the real bytes requires the offline
research VM (`docs/genuine-malware-evaluation-plan.md`) and is a listed blocker below.

## Limitations and false-positive risks

- **Signatures are validated on inert fixtures and benign binaries only**, not against genuine
  malware. Family-specific rules against real samples are authored and validated in the offline VM.
- `ELF_UPX_Tampered_Header` also matches protected commercial software and a UPX banner embedded
  as data; that is why it is MEDIUM and cannot raise the verdict.
- The practical effect on real files today is context, not new MALICIOUS verdicts: genuine ELF
  malware without a validated signature stays SUSPICIOUS (blocked, not called SAFE).
- Dynamic/needed-library reading is section-based; a file with no section headers yields no library
  list (itself a weak indicator), never a crash.
- Structural indicators are intentionally weak; they explain and corroborate, they do not convict.

## Performance (local, Windows, fresh process)

Parse + scan is independent of file size (headers only): ~0.02 ms on a 772 B or a 1.2 MB ELF.
Worst bounded case (8000 sections) ~6 ms median / ~12 ms max; an over-limit header is rejected in
~0.004 ms. Added peak memory ~1 MiB working set. Existing rlimits/timeouts are unchanged.

## Tests

- `tests/test_elf.py`: parser indicators and bounds, scanner severities, end-to-end
  verdicts, a modified UPX header never MALICIOUS, only validated rules HIGH, `Native_Executable` replacement, fail-closed on
  malformed, reference engine unchanged.
- `tests/test_elf_linux.py` (CI, Linux): real system binaries from `/bin`, `/usr/bin`,
  `/usr/lib`/`/lib` must not be MALICIOUS and must parse; fails rather than skips in CI if too few
  are found.
- Fixtures are built in memory (`tests/elf_fixtures.py`); no binary or malware is committed.

## Remaining blockers to genuine-malware validation

1. Verify the research VM is offline and its containment controls are intact.
2. Confirmed sample-transfer procedure (the Emotet-pilot containment approvals are still pending).
3. Only then: scan `7f14bb23…` in the VM, attribute the family, and author/validate family
   signatures against the real bytes. No genuine malware is committed to GitHub, CI or public staging.
