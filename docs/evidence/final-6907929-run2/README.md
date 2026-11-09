# Final offline VM validation, run 2 at `6907929` (2026-11-09): superseded, kept as found

Offline Ubuntu VM `FilesMagic-securityLAB`, confined interpreter `filesmagic-eval-python (enforce)`,
strict isolation. Inert synthetic cases and the committed benign corpus only. Procedure:
[docs/offline-vm-validation-phase6.md](../../offline-vm-validation-phase6.md), Section 7. Run 1
(`d80a46d`) is kept unchanged in [final-d80a46d-run1/](../final-d80a46d-run1/README.md).

## Outcome

| Step | Result |
|---|---|
| Disc integrity in the guest (`sha256sum -c SHA256SUMS` on the read-only mount, before installing) | 7/7 OK; `COMMIT.txt` and bundle head `6907929172732e4d5dc9468e20629d74320b44b4` |
| Install | clean tree at `6907929`; disc unmounted (`udisksctl`) |
| `guest_checks.sh` | every control PASS (`final-6907929-guest-checks.txt`) |
| `evaluation.offline_validation` (03:39:50Z to 03:51:20Z) | completed, exit 0: **11/11 claims PASS**; 102/102 identical to the Windows evidence; 12/12 C7 verdicts as expected; strict isolation on every trial |
| Test suite (`final-6907929-pytest.log`, `.xml`) | 1004 tests: 992 passed, **1 failed**, 11 skipped, 0 errors |

The 11 skips are exactly the expected environment skips (Section 5.5), each with its demonstrated
reason: 9 in `tests/test_vm_scripts.py` (the profile refuses to start bash), and the two offline-host
skips (interfaces `['lo']`, 0 IPv4 routes, all IPv6 routes on `lo`).

Process-group termination **was verified** in this run:
`test_process_group_is_killed_including_grandchildren` passed in both modes (`spawn-sleep` 2.0 s,
`spawn-exit` 2.1 s, deadline 5 s), and `test_a_surviving_grandchild_is_detected` passed. With the
run-1 correction a zombie counts as not ended, so passing means the grandchild was killed and
reaped within the deadline.

## The failure: a wrong expectation in a new regression test

`tests/test_worker_linux.py::test_process_observation_on_real_processes` (added by the run-1
correction) kills its own child and expected `/proc/<pid>/stat` to show it as a zombie (state
`Z`). Under the profile that read was refused (18 audit lines for `/proc/14701/stat`, `ouid=0`), so
`tests/processes.alive` fell back to `kill(pid, 0)`, which a zombie accepts: it reported "not
ended", as designed. The test's assertion "not a zombie within 5 s" therefore failed.

Cause, measured after the run (`final-6907929-zombie-ownership.txt`: unconfined system `python3`
and `sleep 30`, no document): while the process runs, `/proc/<pid>/stat` is owned by uid 1000;
once it is a zombie (confirmed with `waitid(WNOWAIT)`, state `Z`) the same file is owned by
**uid 0**, while `/proc/<pid>` stays at 1000. The profile allows only `owner @{PROC}/@{pid}/stat r`,
so a zombie's `stat` can never be read by the confined interpreter. This is consistent with run 1,
where the grandchild's entry was also `ouid=0` at the first read. The measurement behaved as
specified (never "ended" when unobservable); the test's expectation did not hold under confinement.
No implementation defect is shown. The test is corrected in a later commit (it observes the zombie
independently with `waitid(WNOWAIT)` and expects "not ended" when `/proc` is refused), and the
whole validation is rerun (`final-<sha>-run3`).

## Files

| File | What |
|---|---|
| `final-6907929/` | `report.md`, `results.json`, `run_status.json`, `SHA256SUMS` (checks the three; 3/3 OK in the guest) |
| `final-6907929.log` | the validation's console log |
| `final-6907929-guest-checks.txt` | isolation checks before scanning |
| `final-6907929-pytest.log`, `final-6907929-pytest.xml` | the suite: log with `-rfs`, JUnit XML (per-test skip reasons) |
| `final-6907929-apparmor-denials.txt` | every AppArmor denial in the kernel log between the run's start and end (46) |
| `final-6907929-zombie-ownership.txt` | the post-run ownership measurement above (2026-11-09T04:05:14Z) |
| `final-6907929-guest-sha256.txt` | SHA-256 of the 10 files above, taken in the guest before the copy |

All 10 match `final-6907929-guest-sha256.txt` on the host (copied with `VBoxManage guestcontrol
copyfrom`). The denials file holds only kernel audit lines from the test suite's probes:
- 14 `exec`: 10 of bash, 4 of `uname` (the platform probe);
- 11 `mknod`: `.git/index.lock`, from git status probes;
- 1 `create`: inet stream, the namespace-connect test (accepted);
- 1 `capable`: `net_admin`, the capability precondition (accepted);
- 19 `open`: 18 of `/proc/14701/stat` (the failing test's child, a zombie; the kernel log holds
  fewer lines than reads) and 1 of `/proc/14700/stat` in the same second (which process held that
  PID is not recorded).
