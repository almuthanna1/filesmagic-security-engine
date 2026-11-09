# Phase 6: offline VM validation of the unified engine

**FilesMagic Security Engine · NIU CSCI 499 Honors Capstone**

Validates the current unified engine, next to the original four-scanner engine, inside the
offline Ubuntu VM validated in [offline-vm-validation-c9-2.md](offline-vm-validation-c9-2.md)
(C9.2) and last used for the EICAR/Didier run at `c8bf8dd` (2026-11-04). Inert synthetic and
known-benign files only: **no genuine malware and no EICAR material**. Run 2026-11-09 at `996db77`:
every isolation check PASS, 9/9 contribution claims PASS, 102/102 scan results identical to the
Windows evidence (Section 5).

## 1. What is transferred, and why nothing else

The transfer ISO (`evaluation/vm/build_transfer_iso.ps1`, without `-Samples`/`-Acquired`) holds
only the committed source and its integrity data:

| File | What |
|---|---|
| `filesmagic.bundle` | the branch as a git bundle (installed as a new ref; nothing in the VM is reset or merged) |
| `source-<sha>.tar` | `git archive` of the commit, for inspection |
| `COMMIT.txt`, `BRANCH.txt`, `MANIFEST.txt` | commit id, branch, tree, parents, commit time, subject, `requirements.txt` blob |
| `install_from_iso.sh` | taken from the commit itself |
| `SHA256SUMS` | over every file; the ISO's own hash is written next to it on the host |

Everything the run scans comes from that commit: the original four scanners and the unified
engine (`app/`), the 16 inert synthetic cases (built by `evaluation.cases` from `tests/` fixture
builders), the benign corpus committed under `evaluation/benign_corpus/` (29 authored files and
4 public U.S. government documents, each pinned by SHA-256 in its manifest), and two truncated
documents derived from them. The builder refuses uncommitted or unpushed code, a commit that
contains the EICAR signature, and (study mode only) samples that do not match their manifest.

No dependency changed since `c8bf8dd` (`git diff c8bf8dd HEAD -- requirements.txt` is empty), so
the VM's offline environment `/opt/filesmagic/venv` is expected to match; the run checks it.

## 2. Who does what

| Step | Where | Who |
|---|---|---|
| A. Build the ISO from a clean worktree of the pushed commit; verify its hashes | host | Claude |
| B. Check the VM's host-side settings (`showvminfo`, read-only) | host | Claude |
| C. Attach the ISO to the powered-off VM's optical drive | VirtualBox | **you** (or Claude with your approval: one `storageattach`) |
| D. Boot, log in, mount the ISO read-only, run `install_from_iso.sh`, unmount | guest console | **you** (`mount` needs sudo; the login is yours) |
| E. Run `guest_checks.sh`; stop if it reports STOP | guest console | **you** |
| F. Run `evaluation.offline_validation`, then the test suite | guest console | **you** |
| G. Copy the results out (metadata only) | host ↔ guest | **you** (Section 4) |
| H. Shut down, detach the ISO; re-check host settings; verify hashes; compare and report | host | you (shutdown), Claude (the rest) |

As run (2026-11-09), steps D-G went through VirtualBox Guest Control at your request: you
prepared a temporary password file on the host (`%LOCALAPPDATA%\fm-gc\guest.pw`, never read,
printed or committed), and Claude passed only its path to `VBoxManage guestcontrol`. The disc
was GNOME's read-only auto-mount, unmounted with `udisksctl` (no sudo). Nothing in these steps
changes the VM's isolation settings, the AppArmor profile or a snapshot.

## 3. Commands inside the guest (steps D-F)

```bash
# D. install (from the read-only medium)
sudo mkdir -p /mnt/fm-eval-iso && sudo mount -o ro -t udf /dev/sr0 /mnt/fm-eval-iso
bash /mnt/fm-eval-iso/install_from_iso.sh          # verifies SHA256SUMS, fetches the commit, checks it out
sudo umount /mnt/fm-eval-iso

# E. isolation checks (read-only, no root); any STOP: do not continue, report it
C=$(git -C ~/filesmagic-security-engine rev-parse HEAD); R=~/fm-eval/results/phase6-${C:0:7}
bash ~/filesmagic-security-engine/evaluation/vm/guest_checks.sh | tee $R-guest-checks.txt

# F. both engines through the isolated worker, strict isolation; then the tests
cd ~/filesmagic-security-engine
SECURITY_ENGINE_REQUIRE_ISOLATION=1 /opt/filesmagic/venv/bin/python -B -m evaluation.offline_validation \
    --expect-commit $C --out $R 2>&1 | tee $R.log
/opt/filesmagic/venv/bin/python -B -m pytest -q -rfs -p no:cacheprovider --junitxml $R-pytest.xml tests 2>&1 | tee $R-pytest.log
```

`guest_checks.sh` verifies what the guest sees:
- only `lo`, and no non-local IPv4 or IPv6 route;
- route lookups unreachable;
- no shared or network file systems mounted;
- the dedicated interpreter's ownership and permissions;
- the profile file's SHA-256 against the C9.2 value;
- the interpreter running as `filesmagic-eval-python (enforce)`;
- the user-namespace restriction left at 1.

`evaluation.offline_validation` then refuses to scan (exit 3) unless:
- strict isolation is set and the process is confined in enforce mode;
- the host has no usable route;
- the expected commit is checked out with a clean tree;
- there is no dependency drift;
- every corpus file matches its manifest;
- a preflight scan in each engine reports every required control and that engine's scanners.

It re-checks every trial of every scan and stops at the first that fails. Exit 1 means it
completed but one of the contribution checks failed.

Expected in the test run, from the release-freeze commit on: 0 failures, and exactly the
environment skips of Section 5.5 (11 in this VM), each listed with its reason in the log and the
JUnit XML. At `996db77` (before Section 5.5) the run had 13 failures (Section 5.4). Any failure, or
any other skip with an `unsupported environment` reason, is a discrepancy.

## 4. Getting the results out (step G)

Copy the results directory and the three logs:
- `phase6-<sha7>/` holds `report.md`, `results.json`, `run_status.json` and `SHA256SUMS`;
- the logs are `-guest-checks.txt`, `.log` and `-pytest.log`.

They hold verdicts, rule ids, descriptions, timings and hashes, never document bytes. Options:
1. **VirtualBox Guest Control** (as for `c8bf8dd`), run by you on the host with your guest
   credentials, while the VM runs:
   `VBoxManage guestcontrol FilesMagic-securityLAB copyfrom --username <you> --target-directory <host dir> --recursive <guest dir>`.
   It is a host-to-guest channel through the Guest Additions, used only for this copy.
2. **Read-only review on screen**: `report.md` alone is enough for the verdict-level comparison,
   but not reproducible evidence.

Before the copy, hash the files in the guest (`sha256sum` into `$R-guest-sha256.txt`) so the
host copy can be checked against it.

## 5. Results

Evidence: [evidence/phase6-996db77/](evidence/phase6-996db77/) (copied out with Guest Control;
all 8 files match the SHA-256 values taken inside the guest).

### 5.1 First attempt stopped at `6ffd413` (defect in the check, not the VM)

`guest_checks.sh` reported STOP on "interpreter tree". The cause was 1053 root-owned symlinks
in `/opt/filesmagic`, counted as writable because `find -perm /022` matches every link (a
link's own mode is always 777). Nothing was scanned. The check was replaced by
`evaluation/vm/trusted_tree.sh` (`e755786`, `996db77`). It judges each link by its owner and by
its resolved target, rejects dangling, looping or escaping links, and has 10 regression tests.
A new ISO was built from a clean worktree of `996db77` and swapped in with `storageattach`; only
the IDE 0-0 medium changed in `showvminfo`.

### 5.2 Run at `996db77`

| Item | Result |
|---|---|
| Commit, tree | `996db77bdd248d36b75e59310f789c02235cd696`, clean |
| Platform | Ubuntu 24.04, kernel 7.0.0-38-generic, 4 vCPU, 8 GiB; Python 3.11.18 (confined interpreter); zlib 1.3.2 |
| Guest checks | all PASS: `lo` only, 0 routes, lookups unreachable, no shared mounts, interpreter root-owned, tree 7773 entries and 1053 links with 0 problems, profile SHA-256 unchanged, `filesmagic-eval-python (enforce)`, userns restriction 1 |
| Strict isolation | every trial of every scan, both engines: no missing control (`isolation_missing` empty) |
| Scanner status | preflight: every scanner of each engine reported; no scanner failed on any corpus or synthetic file |
| Claims | 9/9 PASS (5a, 5b, refined YARA-X rule both ways, VBA call path, OOXML correlation, the three FP corrections, docx-05, fail-closed) |
| Determinism | all 102 results the same in every trial (20 synthetic, 5 corpus and corrupt) |
| Against Windows | 102/102 scan results identical: verdict and every finding, INFO included |
| Against staging (`9111e5a`) | the 12 files run in both places: all 24 verdicts and rule sets equal |
| Failure handling | truncated PDF and DOCX: UNABLE_TO_SCAN in both engines, the parsing scanners listed as failed |

**Byte differences, not result differences.** The 8 DOCX synthetic cases have other SHA-256
values than on Windows and staging. The cases are DEFLATE-compressed ZIPs. Windows Python
uses zlib-ng 1.3.1, the guest zlib 1.3.2, so the compressed bytes differ while every part's
content is the same (as already recorded for Linux CI in `custom-engine-1668326`). The PDFs
and every corpus file (pinned by manifest) have identical hashes.

**Host restored (2026-11-09).** ACPI shutdown (powered off after 10 s, nothing forced); the drive
set back to `emptydrive`. `showvminfo` against the baseline taken before the swap shows only
optical-drive keys and runtime-only fields changed. Unchanged: nic1-8 `none`, clipboard and drag
and drop disabled, no shared folders, USB, audio, VRDE, serial and parallel ports off, the six
snapshots and the current snapshot "C11 - Offline Research Evaluation Ready".

### 5.3 Latency (median over files of each file's median of 5 or 20 trials, ms)

| | Ubuntu VM ref | Ubuntu VM unified | Windows ref | Windows unified | Staging ref | Staging unified |
|---|---|---|---|---|---|---|
| Synthetic, wall | 298 | 332 | 531 | 553 | - | - |
| Corpus, wall | 302 | 340 | - | - | 6949 | 7229 |

Wall time is dominated by starting the isolated worker process. On Ubuntu that includes the
namespaces, capability drop and rlimits, and is still faster than an unisolated process start
on Windows (Python 3.14, `812bb7d` evidence). Staging is the HTTP round trip to the Render free
tier. Scanner time itself is about 0.2-2.5 ms per scanner on these small files. It is larger
only on the 3 IRS PDFs (pdf about 15-52 ms) and xlsx-02 (office about 16-24 ms). On the
synthetic cases the per-scanner medians are within a few tenths of a millisecond on both
platforms. The unified engine adds about 30-40 ms wall per file on Ubuntu, while its four added
scanners take under 2 ms together on typical files. The rest is worker overhead that this run
does not break down. Timings are from one VM on one laptop and are not a benchmark.

### 5.4 Test suite in the VM

`896 passed, 13 failed` under the confined interpreter (CI on Linux, unconfined: all pass).

| Tests | Cause | Class |
|---|---|---|
| 4 in `tests/test_worker_linux.py` (namespace connect, host-network detection, interface diagnostics, capability precondition) | the VM is offline and the profile denies `network inet` and `net_admin` | the known C9.2 Section 6 failures, unchanged |
| 9 in `tests/test_vm_scripts.py` (all that run `trusted_tree.sh`) | `PermissionError: 'bash'`. The kernel log shows `apparmor="DENIED" operation="exec" profile="filesmagic-eval-python" name="/usr/bin/bash"` | **new, VM-specific, intended**: the profile forbids the confined interpreter from starting a shell. The script itself ran under the guest's normal bash in `guest_checks.sh` and passed on the real tree |

No failure points at the engine. The 9 new ones follow from these tests being added after
C9.2.

In detail (from `phase6-996db77-pytest.log` and the guest kernel log):

| # | Test | Observed | Why | Kind |
|---|---|---|---|---|
| 1 | `test_network_namespace_blocks_connections_when_available` | connect fails with `EACCES` (13), test expects `ENETUNREACH` (101) | the profile has no `network inet stream` rule, so the socket is refused before routing | stronger restriction than the test assumes |
| 2 | `test_network_verification_detects_the_host_network` | the host checks pass; the test expects them to fail | the VM's host namespace is itself `lo` only with no routes | unsupported condition: needs a networked host |
| 3 | `test_diagnostics_read_real_interface_state_in_the_host_namespace` | 1 interface (`lo`), 0 routes; expects a non-loopback interface with a route | same | unsupported condition |
| 4 | `test_capabilities_are_dropped_in_the_kernel_and_cannot_be_regained` | first step `EPERM`; expects `ok` (reconfiguring `lo` before the drop); the 11 later assertions hold | the profile denies `net_admin` before the drop | stronger restriction |
| 5-13 | 9 tests in `tests/test_vm_scripts.py` that run `bash trusted_tree.sh` | `PermissionError: 'bash'`; kernel: `apparmor="DENIED" operation="exec" profile="filesmagic-eval-python" name="/usr/bin/bash"` | the profile does not let the confined interpreter start programs | unsupported condition: needs exec |

### 5.5 Explicit skips for unsupported conditions (approved 2026-11-09, applied)

The aim is that the VM run reports *0 failed* only when nothing is wrong, without hiding a
failure or changing AppArmor. Each failure kind gets its own treatment:

1. **Unsupported condition → an explicit skip, decided by measuring the condition.** No opt-out
   variable is involved, and the reason text goes into the log (`pytest -rs`):
   - Rows 5-13: skip only if *both* hold: the process's AppArmor label (from
     `/proc/self/attr/apparmor/current`) is not `unconfined`, *and* starting `/usr/bin/bash` raises
     `PermissionError`. Reason: "confined as <label>: exec of bash denied (intended); trusted_tree.sh
     is checked by guest_checks.sh and Linux CI". Bash missing or failing for any other reason
     still fails.
   - Rows 2-3: skip only if the host namespace is measured to have only `lo` and no usable
     route. Reason: "offline host: no network to detect". Add one test that asserts the
     opposite in that case (exactly `lo`, `ARPHRD_LOOPBACK` 772, 0 routes), so the offline state
     is positive evidence rather than a skip alone.
2. **Stronger restriction → still a passing assertion, not a skip** (rows 1 and 4). Under a
   confining label, accept `EACCES` for the connect and `EPERM` for the pre-drop step. Keep
   `ENETUNREACH` and `ok` when unconfined. Every later assertion is unchanged. This is the C9.2
   Section 6 proposal.
3. **Guard rails:**
   - Every skip condition requires confinement or an offline host, neither of which GitHub's
     Linux runners have, so CI keeps running and asserting all 13 tests.
   - The VM run's log (`-rs`) and a JUnit XML file (`--junitxml`) list each skip with its test and
     reason. Every such reason starts with `unsupported environment (demonstrated):`, so they are
     counted apart from the platform skips (Linux-only tests on Windows).
   - A skip whose condition does not hold is not taken: the test runs, and fails if it must.

As implemented (`tests/environment.py`, tested by `tests/test_environment.py`):
- `enforced_profile()` reads the process's AppArmor label; complain mode does not count.
- `exec_denied("bash")` needs an enforced profile *and* a `PermissionError` when starting bash.
- `offline_host()` reads `/proc/self/net/{dev,route,ipv6_route}` (allowed by the profile; no
  socket, and not the worker's own checks): only `lo`, and every route on `lo`.
- `unsupported(reason)` skips, or fails with `FM_REQUIRE_LINUX_TESTS=1` (CI).
- New `test_host_network_checks_agree_with_an_independent_measurement` runs everywhere: the
  worker's host-namespace view must equal the `/proc/self/net` measurement, online or offline.

Expected in the VM: 11 skips (rows 2-3 and 5-13), each with its reason; rows 1 and 4 pass under
the enforced profile; 0 failures. On CI: 0 skips.

Nothing here changes the profile, the worker or the isolation checks. It changes only what the
tests assert, in the environment where their assumption is measured to be false.

## 6. What this run can and cannot show

- **Validates functionality** on Ubuntu inside the confined, offline worker:
  - each engine's verdicts and rules on the inert cases and the benign corpus;
  - correlation evidence;
  - failure handling on truncated input;
  - the isolation controls on every scan;
  - per-scanner timing.
- **Remains synthetic evidence**: the 16 cases are constructed indicators; the VBA call graph's
  positive results exist only as unit tests on inert source strings (by design, no macro
  document is built), so through the worker only "call path undetermined" is exercised. A
  MALICIOUS verdict on an inert case is the engine's reading of a constructed indicator, not
  detection of malware.
- **Not measured**: detection of real malware (none is used), worker memory, and any rate.

## 7. Final run (release freeze, with C7)

The final committed code on a new ISO; same procedure (Sections 3-4). Adds the `c7` set (6 inert
Word field-code cases) and the two C7 claims.

**Run 1, at `d80a46d`: superseded, kept as found**
([evidence/final-d80a46d-run1/](evidence/final-d80a46d-run1/README.md)). 11/11 claims; 102/102
results identical to Windows; 12/12 C7 verdicts as expected. The suite had 977 passed, 11 skipped
(the expected skips) and **1 failed**:
`test_process_group_is_killed_including_grandchildren[spawn-exit]`. AppArmor refused the test's
read of the grandchild's `/proc/<pid>/stat`, an entry owned by root (`ouid=0`; the profile allows
only `owner` reads). Process-group termination was therefore **unverified** in that run; no
implementation defect was shown.

**Correction (test measurement only).** `tests/processes.alive` keeps `/proc/<pid>/stat` as the
primary observation. Only when that read is refused does it fall back to `kill(pid, 0)`, and it
reports "ended" only on ESRCH. EPERM, EACCES or success count as not ended: a zombie, an
inaccessible process or a reused PID make the test wait and fail at its deadline, never pass. The
security assertion, the 5-second deadline, the worker, the profile and the isolation settings are
unchanged. Regression tests: `tests/test_processes.py` (every fallback outcome, on every platform)
and, in `tests/test_worker_linux.py`, real processes through running, zombie and reaped under both
observations, plus a surviving process failing `wait_dead`.

**Run 2: pending**, on a new ISO built from the correction's commit, into new result paths
(`final-<sha7>`). Run 1's results are kept.
