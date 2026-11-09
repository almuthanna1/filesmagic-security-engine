# Phase 6 evidence: unified engine in the offline VM, commit `996db77`

Procedure and discussion: [docs/offline-vm-validation-phase6.md](../../offline-vm-validation-phase6.md), Section 5.
Inert synthetic cases and the committed benign corpus only; no genuine malware, no EICAR.

| File | What |
|---|---|
| `phase6-996db77/` | `evaluation.offline_validation` output: `report.md`, `results.json`, `run_status.json`, `SHA256SUMS` |
| `phase6-996db77.log` | its console log |
| `phase6-996db77-guest-checks.txt` | `guest_checks.sh` before the run: every control PASS |
| `phase6-996db77-pytest.log` | the test suite under the confined interpreter: 896 passed, 13 failed (classified in the doc) |
| `phase6-6ffd413-guest-checks.txt` | the earlier, defective check that stopped the first attempt (symlinks counted as writable); kept as the record of why `996db77` exists |
| `phase6-996db77-guest-sha256.txt` | SHA-256 of the 8 files above, taken **inside the guest** before the copy |

All 8 files were copied out with `VBoxManage guestcontrol copyfrom` and match
`phase6-996db77-guest-sha256.txt` on the host (`sha256sum -c phase6-996db77-guest-sha256.txt` from
this directory). `phase6-996db77/SHA256SUMS` also checks. `.gitattributes` keeps them byte-for-byte.
The pytest log contains guest paths under `/home/almuthanna-shihab` (the student's own account
name); nothing else identifies the machine.
