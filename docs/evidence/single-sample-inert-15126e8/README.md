# Inert validation of the single-sample tool at `15126e8` (2026-11-09): passed

Offline Ubuntu VM `FilesMagic-securityLAB`, confined interpreter `filesmagic-eval-python (enforce)`,
strict isolation. **Inert and benign files only: no genuine malware was acquired, transferred or
scanned.** Tool: [evaluation/single_sample.py](../../../evaluation/single_sample.py); plan:
[docs/offline-results-viewer-plan.md](../../offline-results-viewer-plan.md), Section 4.
Earlier evidence is unchanged (final run 3: [final-eda2a08-run3](../final-eda2a08-run3/README.md)).

## Outcome

| Step | Result |
|---|---|
| Host: VM powered off before the swap; `storageattach` IDE 0-0 only (`host/vm-settings-swap-diff.txt`) | only `IDE-0-0` and its image UUID changed; NICs 1–8 `none`, clipboard and drag-and-drop disabled, no shared folders, USB/EHCI/XHCI, serial, parallel, audio and VRDE off, the six snapshots unchanged (`host/vm-isolation-keys.txt`) |
| Host: after boot (`host/vm-settings-boot-diff.txt`) | only runtime keys changed (state, session, video mode, Guest Additions facilities) |
| Disc integrity in the guest (`single-15126e8-logs/disc-integrity.txt`) | `sha256sum -c SHA256SUMS` 7/7 OK; `COMMIT.txt` and bundle head `15126e8d25b8c3f433fa331bc546a7dff9443e97` on `research/offline-single-sample`; **whole disc `/dev/sr0` hashed in the guest = host ISO `619883ac710484a52bfac59b6f38ab5acd2cf1362147a0118c351b80411a9987`**; no EICAR material |
| Install (`install.txt`) | detached checkout at `15126e8`, clean tree; `app/` tree `c50b66c1…` and `requirements.txt` blob `5089f11d…` = the frozen release; the VM repository holds no tags; disc unmounted (`udisksctl`) |
| `guest_checks.sh` 18:40:01Z (`guest-checks.txt`) | every control PASS, 0 STOP: only `lo`, no routes, IPv4/IPv6 unreachable, no shared or network file systems, interpreter tree root-owned (0 problems), AppArmor profile `6a94078…aa20`, confinement enforce, userns restriction unchanged |
| Control: `evaluation.offline_validation` 18:40:44Z–18:51:10Z (`phase6-15126e8/`, `phase6-15126e8.log`) | completed, exit 0, no problems; **11/11 contribution claims PASS; 114/114 results as expected** (102/102 identical to the Windows evidence, 12/12 C7 verdicts); `isolation_missing` empty and deterministic on all 114; scanners failed only on the 2 truncated files (UNABLE_TO_SCAN) |
| Inert fixtures (`write-inert.log`) | the three files match their registered SHA-256 (`evaluation/expectations/inert-*.json`) |
| `single_sample`, 5 trials per engine (`single-inert-*-15126e8/`) | all three **completed · PASS**, every pre-registered check held (20/20, 12/12, 11/11), no defects, preflight complete for both engines |
| Deliberate mismatches (`single-mismatch-*-15126e8/`) | both **stopped, exit 3, before any scan** (no preflight, 0 scans): (A) the truncated file offered under the benign file's hash: "SHA-256 03d51cfd… is not the expected 996c1dee…"; (B) a `--sha256` that is not the registered one: rejected before the file is read |
| Test suite 18:53:42Z (`pytest.log`, `pytest.xml`) | 1035 tests: **1024 passed, 0 failed, 0 errors, 11 skipped**; the 31 `tests/test_single_sample.py` cases all passed |

### Single-sample results

| Fixture | Reference | Unified | Findings (both engines) | Failed scanners |
|---|---|---|---|---|
| `inert-ole-vba-storage` (OLE .doc, empty VBA storage, no code) | SUSPICIOUS | SUSPICIOUS | `yara-x:OLE_Office_VBA_Macros:MEDIUM`, `office:OFFICE_VBA_UNPARSED:LOW` | none |
| `inert-benign-docx` (`docx-01-word-plain.docx`) | SAFE | SAFE | none | none |
| `inert-truncated-docx` (its first half) | UNABLE_TO_SCAN | UNABLE_TO_SCAN | none | reference `office`, `custom`; unified also `vba-chains`, `ooxml-links`, `word-fields` (fail closed) |

Each report (`report.html`) holds metadata only: no `<script>`, no external reference, a
`default-src 'none'` Content-Security-Policy. Each `SHA256SUMS` verifies on the host.

The 11 skips are the expected environment skips: 9 because the profile refuses to start bash,
2 because the host is offline (`lo` only, no IPv4 routes).

## AppArmor denials

All from profile `filesmagic-eval-python`, the same kinds and the same total as run 3 (29):

| File | Count | Kinds |
|---|---:|---|
| `phase6-15126e8-apparmor-denials.txt` | 3 | `git` index.lock (1) and `uname` (2), while the environment is recorded |
| `pytest-apparmor-denials.txt` | 26 | bash refused (10), `git` index.lock (10), `uname` (2), the zombie's `/proc/<pid>/stat` (2), the inet-socket probe (1), the `net_admin` probe (1) |
| `single-inert-apparmor-denials.txt` | 9 | per run: `git` index.lock (1), `uname` (2) |
| `single-mismatch-apparmor-denials.txt` | 6 | the same, for the two stopped runs |

## Latency (one VM on one laptop; not a benchmark)

Median over files of each file's median wall time, dominated by starting the isolated worker:
synthetic 346.2 ms reference / 372.8 ms unified; corpus 287.9 / 346.9 ms; C7 309.6 / 322.9 ms.
Single-sample medians: 290.0 / 323.1 ms (OLE), 1352.3 / 322.8 ms (benign DOCX), 314.6 / 447.1 ms
(truncated). The benign DOCX's reference trials 1–3 took 1.35–1.76 s while its scanners took
15–27 ms together; trials 4–5 took 331 and 310 ms, and the same file took 290 ms in the control
run minutes earlier. The extra time was outside the scanners (worker start-up), 16 minutes after
boot: VM contention, not engine work, and far below the 30 s bound.

## Observed desktop state (read only; `desktop-indexing-state.txt`)

For the containment prerequisites of a live sample (plan Section 5), not changed here:
`tracker-miner-fs-3` running with monitors on (indexes `$HOME` one level, Downloads, and the
XDG folders recursively; not removable or optical media; `~/fm-eval` is not crawled); thumbnails
`local-only` (enabled), `evince.thumbnailer` installed (PDF), no Office thumbnailer; automount and
automount-open on.

## CI

Run 42672822271 for `15126e8`: attempts 1–3 (18:18–18:24Z) each lacked one job that GitHub never
created, during GitHub's critical "Incident with Actions and Checks API" (opened 18:12:37Z;
Actions in major outage until 18:43:24Z). Attempt 4 (18:45Z): **all three jobs passed**: backend
1035 passed, 0 skipped, plus 31 in the tunnel-fallback run; production image; Security Lab.
No configuration change was needed.

## Files

- `single-15126e8-logs/`: disc integrity, install, guest checks, the control run's log, the
  single-sample and mismatch logs, the test suite (`pytest.log`, `pytest.xml`), the AppArmor denials,
  the desktop state.
- `phase6-15126e8/`, `single-*-15126e8/`: the tools' own outputs (`results.json`, `report.md` or
  `report.html`, `run_status.json`, `SHA256SUMS`).
- `single-15126e8-guest-sha256.txt`: SHA-256 of all 41 files above, taken in the guest
  (`a18f7a6e…f35a`). All 41 match on the host after `VBoxManage guestcontrol copyfrom`.
- `host/`: the VM settings diffs and isolation keys, with their `SHA256SUMS`.

The inert fixture files themselves are not committed: `--write-inert` rebuilds them from the
source, byte for byte (their hashes are in `write-inert.log`).

## Addendum: intended input path `~/fm-eval/samples/` (same session)

`samplepath/`: the confined interpreter read a benign fixture copied under
`~/fm-eval/samples/inert-samplepath/` and scanned it — `completed · PASS`, both engines SAFE,
deterministic, `isolation_missing` empty, and **no AppArmor denial on the samples path** (the
3 denials in the window are the usual `git` index.lock and `uname`). This confirms the path the
real sample will use, and that the profile grants the read. Verified against
`samplepath/SHA256SUMS-samplepath.txt` (`b8ab484b…e992`).

A later commit (`47fb891`) adds `inert-benign-macro-doc`, a benign document carrying a **real**
VBA module (AutoOpen computing 2 + 2), so the actual oletools extraction path is exercised, not the
mocked results the unit tests use. Validated on the host (both engines SUSPICIOUS: the
auto-execution macro is detected, no dangerous capability, so not MALICIOUS) and in CI (run
42681865761, all three jobs; backend 1038 passed). Its in-VM run awaits approval to swap to the
`47fb891` transfer ISO.
