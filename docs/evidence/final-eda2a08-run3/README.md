# Final offline VM validation, run 3 at `eda2a08` (2026-11-09): passed, the release evidence

Offline Ubuntu VM `FilesMagic-securityLAB`, confined interpreter `filesmagic-eval-python (enforce)`,
strict isolation. Inert synthetic cases and the committed benign corpus only. Procedure:
[docs/offline-vm-validation-phase6.md](../../offline-vm-validation-phase6.md), Section 7. The
earlier runs are kept unchanged: [run 1](../final-d80a46d-run1/README.md) (`d80a46d`) and
[run 2](../final-6907929-run2/README.md) (`6907929`).

## Outcome

| Step | Result |
|---|---|
| Disc integrity in the guest (`sha256sum -c SHA256SUMS` on the read-only mount, before installing) | 7/7 OK; `COMMIT.txt` and bundle head `eda2a08a26f2014876761905d19d20d383225d82` (ISO SHA-256 `86accc9c8e41a1c7b416abf03c1d28f8b0b5ade00799bece96247cd3b9dbd779`) |
| Install | clean tree at `eda2a08`; disc unmounted (`udisksctl`) |
| `guest_checks.sh` (04:15:34Z) | every control PASS, 0 STOP (`final-eda2a08-guest-checks.txt`) |
| `evaluation.offline_validation` (04:15:50Z to 04:27:58Z) | completed, exit 0, status `completed`, no problems |
| Contribution checks | **11/11 PASS** |
| Results | **114/114** as expected: 102/102 identical to the Windows evidence (verdict and every finding, INFO included) and 12/12 C7 verdicts as expected |
| Strict isolation | `isolation_missing` empty on all 114 results; preflight complete for both engines |
| Determinism | all 114 results the same in every trial (20 synthetic and C7, 5 corpus and corrupt) |
| Failure handling | scanners failed only on the 2 truncated files, which are UNABLE_TO_SCAN in both engines |
| Test suite (04:29:08Z; `final-eda2a08-pytest.log`, `.xml`) | 1004 tests: **993 passed, 0 failed, 0 errors**, 11 skipped |

The results cover 57 inputs through both engines: 16 synthetic cases, the 33-file benign corpus
(29 development files and 4 held-out government documents), 2 corrupt files and the 6 C7 cases.

The 11 skips are exactly the expected environment skips (Section 5.5), each with its demonstrated
reason:
- 9 in `tests/test_vm_scripts.py`: the profile refuses to start bash;
- `test_network_verification_detects_the_host_network` and
  `test_diagnostics_read_real_interface_state_in_the_host_namespace`: offline host (interfaces
  `['lo']`, 0 IPv4 routes, all IPv6 routes on `lo`).

Process-group termination is verified: `test_process_group_is_killed_including_grandchildren`
passed in both modes (`spawn-sleep` 2.02 s, `spawn-exit` 2.02 s, deadline 5 s), and
`test_a_surviving_grandchild_is_detected` passed. A zombie counts as not ended, so passing means
the grandchild was killed and reaped within the deadline. The corrected
`test_process_observation_on_real_processes` passed (0.03 s), on the path where the profile refuses
`/proc` for the zombie.

## Verdicts where the engines differ

| Input | Reference | Unified | Why |
|---|---|---|---|
| synthetic 5a (automatic script, unrelated attachment) | MALICIOUS | SUSPICIOUS | the attachment is not on the automatic chain |
| corpus `docx-04`, `xlsx-04` (local picture, local linked workbook) | SUSPICIOUS | SAFE | every target is loaded as data from a local drive path |
| corpus `pdf-07` (LibreOffice hybrid PDF) | SUSPICIOUS | SAFE | the attachment is verified as an OpenDocument file without code or external references |
| held-out IRS `f1040`, `fw4`, `fw9` | MALICIOUS | SUSPICIOUS | automatic JavaScript, but it delivers no attachment (`ENGINE_PDF_AUTO_CHAIN_SCRIPT`, MEDIUM, stays) |
| C7 `c7a` (nested DDEAUTO) | SAFE | MALICIOUS | the program is built by a nested field and treated as unknown |
| C7 `c7c`, `c7d` (remote INCLUDETEXT, file-share INCLUDEPICTURE) | SAFE | SUSPICIOUS | content fetched from outside the document |

Every other input has the same verdict in both engines (docx-05 stays SUSPICIOUS: its local
template is lowered to LOW, not cleared).

## Latency (one VM on one laptop; not a benchmark)

Median over files of each file's median wall time, which is dominated by starting the isolated
worker: synthetic 409.5 ms reference, 435.7 ms unified; corpus 279.1 and 316.4 ms; C7 294.6 and
341.3 ms. The five engine scanners together take a median of 2.1 ms (synthetic), 5.2 ms (corpus;
at most 53.3 ms, on the IRS forms) and 1.6 ms (C7) per file.

## Files

| File | What |
|---|---|
| `final-eda2a08/` | `report.md`, `results.json`, `run_status.json`, `SHA256SUMS` (checks the three; 3/3 OK in the guest) |
| `final-eda2a08.log` | the validation's console log |
| `final-eda2a08-guest-checks.txt` | isolation checks before scanning |
| `final-eda2a08-pytest.log`, `final-eda2a08-pytest.xml` | the suite: log with `-rfs`, JUnit XML (per-test skip reasons) |
| `final-eda2a08-apparmor-denials.txt` | every AppArmor denial in the kernel log between the run's start and end (29) |
| `final-eda2a08-guest-sha256.txt` | SHA-256 of the 9 files above, taken in the guest before the copy |

All 9 match `final-eda2a08-guest-sha256.txt` on the host (copied with `VBoxManage guestcontrol
copyfrom`). Every denial is from profile `filesmagic-eval-python`, made by the test suite's probes:
- 14 `exec`: 10 of bash, 4 of `uname` (the platform probe);
- 11 `mknod`: `.git/index.lock`, from git status probes;
- 1 `create`: inet stream, the namespace-connect test (accepted);
- 1 `capable`: `net_admin`, the capability precondition (accepted);
- 2 `open`: both `/proc/20871/stat` (`ouid=0`). That matches the corrected test's two reads of its
  zombie child, its direct read and `alive()`'s, both refused as the test expects under the
  profile. Which process held that PID is not recorded.
