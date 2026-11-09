# Final offline VM validation, run 1 at `d80a46d` (2026-11-09): superseded, kept as found

Offline Ubuntu VM `FilesMagic-securityLAB`, confined interpreter `filesmagic-eval-python (enforce)`,
strict isolation. Inert synthetic cases and the committed benign corpus only. Procedure:
[docs/offline-vm-validation-phase6.md](../../offline-vm-validation-phase6.md), Section 7.

## Outcome

| Step | Result |
|---|---|
| Disc integrity in the guest (`sha256sum -c SHA256SUMS` on the read-only mount, before installing) | 7/7 OK; `COMMIT.txt` and bundle head `d80a46d30183088c384296ee59bd60744dc0f2ed` |
| Install | clean tree at `d80a46d`; disc unmounted (`udisksctl`) |
| `guest_checks.sh` | every control PASS (`final-d80a46d-guest-checks.txt`) |
| `evaluation.offline_validation` | completed, exit 0: **11/11 claims PASS**; 102/102 identical to the Windows evidence; 12/12 C7 verdicts as expected; strict isolation on every trial |
| Test suite (`final-d80a46d-pytest.log`, `.xml`) | 989 tests: 977 passed, **1 failed**, 11 skipped |

The 11 skips are the expected environment skips (docs Section 5.5), each with its demonstrated
reason: 9 in `tests/test_vm_scripts.py` (the profile refuses to start bash), and
`test_network_verification_detects_the_host_network` and
`test_diagnostics_read_real_interface_state_in_the_host_namespace` (offline host: interfaces
`['lo']`, 0 IPv4 routes, all IPv6 routes on `lo`).

## The failure: process-group termination was not verified

`tests/test_worker_linux.py::test_process_group_is_killed_including_grandchildren[spawn-exit]`
checks that a grandchild of the worker (`sleep 60`) is dead within 5 seconds after the worker
fails. It observes the grandchild by reading `/proc/<pid>/stat`. In this run the first read
raised `PermissionError`, and the kernel logged the denial:

    apparmor="DENIED" operation="open" profile="filesmagic-eval-python" name="/proc/8576/stat"
    requested_mask="r" fsuid=1000 ouid=0

The profile allows `owner @{PROC}/@{pid}/stat r`, and this entry was owned by root (`ouid=0`), so
AppArmor refused the observation. **The property was therefore unverified in this run.** The
test neither showed the grandchild dead within the deadline nor showed it surviving. Checked
afterwards from the guest's unconfined shell: PID 8576 no longer existed and no worker or
`fake_worker` process remained. That shows it ended at some point, not within 5 seconds. The
same test passed at `996db77` (Phase 6), where the grandchild was already gone at the first read.
It passes on Linux CI (unconfined). No implementation defect is shown. The test's measurement is
corrected in a later commit, and the whole validation is rerun (`final-<sha>-run2`).

## Files

| File | What |
|---|---|
| `final-d80a46d/` | `report.md`, `results.json`, `run_status.json`, `SHA256SUMS` (checks) |
| `final-d80a46d.log` | the validation's console log |
| `final-d80a46d-guest-checks.txt` | isolation checks before scanning |
| `final-d80a46d-pytest.log`, `final-d80a46d-pytest.xml` | the suite: log with `-rfs`, JUnit XML (per-test skip reasons) |
| `final-d80a46d-apparmor-denials.txt` | every AppArmor denial in the kernel log between the run's start and end (29) |
| `final-d80a46d-guest-sha256.txt` | SHA-256 of the 9 files above, taken in the guest before the copy |

All 9 match `final-d80a46d-guest-sha256.txt` on the host (copied with `VBoxManage guestcontrol
copyfrom`). The denials file holds only kernel audit lines from the test suite's probes:
- 14 `exec`: bash, plus 2 `uname` from the platform probe;
- 12 `mknod`: `.git/index.lock`, from git status probes;
- 1 `create`: inet stream, the namespace-connect test, now accepted;
- 1 `capable`: `net_admin`, the capability precondition, now accepted;
- 1 `open`: the `/proc/8576/stat` read above.
