# Phase 6: offline VM validation of the unified engine

**FilesMagic Security Engine · NIU CSCI 499 Honors Capstone**

Validates the current unified engine, next to the original four-scanner engine, inside the
offline Ubuntu VM validated in [offline-vm-validation-c9-2.md](offline-vm-validation-c9-2.md)
(C9.2) and last used for the EICAR/Didier run at `c8bf8dd` (2026-11-04). Inert synthetic and
known-benign files only: **no genuine malware and no EICAR material**. Results: pending (Section 5).

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

Claude does not log in to the guest: that needs your credentials. Nothing in these steps
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
/opt/filesmagic/venv/bin/python -B -m pytest -q -rf -p no:cacheprovider tests 2>&1 | tee $R-pytest.log
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

Expected in the test run: the four `tests/test_worker_linux.py` failures recorded in C9.2,
Section 6, which come from the VM being offline and confined (proposed corrections still
unapproved). Any other failure is a discrepancy.

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

Pending.

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
