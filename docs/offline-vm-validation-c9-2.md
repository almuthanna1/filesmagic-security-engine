# Offline research VM validation (Phases C9.2A-C9.2D)

**FilesMagic Security Engine · NIU CSCI 499 Honors Capstone · evidence cut-off 2026-10-27**

This document consolidates the evidence from validating the actual offline Ubuntu VM that a
supervisor-approved evaluation would use. It covers benign and inert synthetic files only.
**No genuine malware was downloaded, imported, opened or scanned.**

**Technical readiness is not authorization.** These results show that the environment works. They
do not approve handling genuine malware. That still requires:

- the supervisor's approval;
- approval of the sample-handling procedure, which is still a proposal;
- any applicable NIU authorization;
- dataset approval;
- host disk-encryption verification;
- a finalized procedure for transferring samples into the VM and exporting results.

See [research-readiness-summary.md](research-readiness-summary.md), Section 6.

**Evidence types used below.**

- **VM measurement:** observed in this VM in Phases C9.2A-C9.2D.
- **Linux CI:** GitHub Actions results, cited only for context.
- **Proposed:** not done; requires approval.

Every value below was read from the VM's own output during these phases (terminal output
captured by the operator) or from files that remain inside the VM, listed in Section 9. Nothing
is estimated.

## 1. Environment

| Item | Value |
|---|---|
| Host | Windows 11; Intel Core Ultra 7 258V, 31.5 GB RAM; VirtualBox 7.2.20. The VM runs through the Windows hypervisor ("VT-x is not available" to VirtualBox, because virtualization-based security is active) |
| VM | `FilesMagic-securityLAB`, 4 vCPU, 8.4 GB RAM, 25 GB VDI (unencrypted), BIOS firmware |
| VM isolation | Adapters 1-8 `none`; USB controllers off (PS/2 mouse and keyboard); audio off; clipboard and drag-and-drop disabled; no shared folders; remote display and autostart off; optical drive empty |
| Network use | NAT only for software installation, 2026-10-27 14:52:19-15:15:08 UTC (Phase C9.2B); offline before and after. Offline boots showed only `lo` and 0 IPv4 / 0 IPv6 routes |
| Guest OS | Ubuntu 24.04.5 LTS (noble), kernel `7.0.0-38-generic`; updated from `archive.ubuntu.com` and `security.ubuntu.com` only (78 packages upgraded; no new kernel) |
| Engine | `filesmagic-security-engine` at `b1a69462c9593e81d02ab290410da026f26071c9`, clean working tree; engine 0.2.0; rule set `0be9918509e95e639f866291dc297c45c8e72812d602fb149fad3484435ae3b0` |
| Tooling | uv 0.13.6 (release archive SHA-256 `f29c3e94ffabd7e6f3ba521dba169a9b7ec12100bf3257087f0f24f6123f3645`, verified against the published checksum file, which comes from the same release); CPython 3.11.18 managed by uv |
| Packages (pinned) | yara-x 1.21.0, oletools 0.60.2, olefile 0.47, pypdf 6.19.0, msoffcrypto-tool 6.0.0, defusedxml 0.7.1, FastAPI 0.142.4, pydantic 2.13.5, cryptography 50.0.2, uvicorn 0.54.0, httpx 0.28.1, pytest 9.1.1 (PyPI; version pins, no hash pins) |

## 2. Dedicated interpreter

- **Path:** `/opt/filesmagic/python/cpython-3.11.18-linux-x86_64-gnu/bin/python3.11`, a full copy of
  the uv-managed runtime, made offline.
- **Permissions:** every path component is `root root` (directories `755`, interpreter
  `-rwxr-xr-x`). `find /opt/filesmagic` reported 0 non-root-owned and 0 group/other-writable
  entries.
- **Environment:** `/opt/filesmagic/venv` (root-owned), rebuilt offline from uv's cache.
  `bin/python` resolves to the interpreter above.
- **Initialization:** all three scanners (YARA-X, Office, PDF) initialize under it.

## 3. AppArmor

- **Ubuntu's default behaviour** (`kernel.apparmor_restrict_unprivileged_userns=1`): creating a
  user namespace moves the process into the `unprivileged_userns` profile, which begins with
  `audit deny capability,`. The audit log showed
  `apparmor="DENIED" operation="capable" profile="unprivileged_userns" capname="setpcap"`. The
  worker therefore could not drop its bounding set, and strict mode correctly refused to scan.
- **Correction:** the confined profile `filesmagic-eval-python` (Appendix A), attached only to the
  dedicated interpreter, is installed in enforce mode.
  - Installed file: `/etc/apparmor.d/filesmagic-eval-python`, `root root 0644`.
  - SHA-256: `6a94078413be722c955cea9f63c8eefe9e3bd0c4f7530d381424fce81681aa20`.
  - No complain flag.
  - Not changed: AppArmor was not disabled, and the restriction sysctl was not changed.
- **Mode evidence:** the interpreter reports `filesmagic-eval-python (enforce)` after the final
  load, after a reboot, and again in Phase C9.2D. The system `python3` stays `unconfined`.
- **How the policy was derived:**
  - Complain mode was run once. The kernel's printk rate limit suppressed about 11,000 audit
    records, so that log was incomplete and was used only as a hint.
  - The policy was then set to enforce and refined in three runs:
    1. Denied `sys_admin`, `/proc/<pid>/net/route` (owner rule), `.git/index.lock` creation and
       `terminfo`. The strict preflight aborted, failing closed.
    2. Denied `/proc/<pid>/stat`, plus the intended denials.
    3. Final run: only the intended denials, with 0 suppressed records.
- **Intended denials in the final enforce run:**
  - `net_admin`: the probe and the capability test;
  - TCP socket creation: the connection test;
  - executing `/usr/bin/uname`: Python's `platform` module, so the processor field is blank.
- **Git:** `git` runs under the same profile with `GIT_OPTIONAL_LOCKS=0`. No write to `.git` is
  granted, and `working_tree_dirty` was recorded correctly as `False`.

## 4. Capability drop (engine code, enforce mode)

The probe ran `app.worker.network_isolation()` and `drop_capabilities()` in a throwaway process
(`~/c92c3/probe.final.json`):

- **Confinement:** the label stays `filesmagic-eval-python (enforce)` after `unshare`.
- **Before the drop:** reconfiguring `lo` (`SIOCSIFFLAGS`) fails with `EPERM`; `net_admin` is
  denied by the profile.
- **After the drop:**
  - `capabilities_dropped=true`;
  - `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` are all `0000000000000000`;
  - `NoNewPrivs: 1`, `Threads: 1`;
  - securebits `239` (0xEF, all locks set);
  - reconfiguring `lo` and `capset` re-raising `CAP_NET_ADMIN` both return `EPERM`.

The repository test's own `CAP_PROBE`, run unchanged in Phase C9.2D
(`~/c92c3/cap_probe_full.c92d.txt`), additionally showed:

- an ambient raise returns `EPERM`;
- `PR_CAPBSET_READ(CAP_NET_ADMIN)` returns `0`;
- unlocking the securebits returns `EPERM`;
- `setuid(0)` returns `EINVAL`;
- an executed child has empty capability sets and `NoNewPrivs: 1`;
- creating a nested user namespace returns `EPERM`, and reconfiguring `lo` after it returns `EPERM`.

## 5. Strict preflight and harmless evaluation

Both runs used `SECURITY_ENGINE_REQUIRE_ISOLATION=1`, the root-owned environment and the profile
in enforce mode.

| Run | Preflight request | Verdict | complete | isolation_required | isolation_missing | Run status |
|---|---|---|---|---|---|---|
| Final (`~/fm-eval/results/c92c-final`) | `fd643c6202414a78` | SAFE | true | true | `[]` | completed |
| After reboot (`…/c92c-after-reboot`) | `69e6672af4304ecd` | SAFE | true | true | `[]` | completed |

**Preflight isolation values (final run), all true:**

- `process`, `network_namespace`, `network_verified`, `net_interfaces_safe`;
- `net_ipv4_no_route`, `net_ipv6_no_route`, `net_ipv4_unreachable`, `net_ipv6_unreachable`;
- `capabilities_dropped`, `rlimits`, `audit_hook`.

The VM is loopback-only, so `net_loopback_only=true` and `net_fallback_tunnel_inert=false`.

**Inert fixtures** (from the repository's own builders; manifest `~/fm-eval/manifest.csv`):

| Sample | Ground-truth label | Result | Request | Required controls |
|---|---|---|---|---|
| C92C-B-0001 harmless DOCX | BENIGN | SAFE, complete | `4cc90b87e4ac4167` | all true, `isolation_missing=[]` |
| C92C-B-0002 harmless PDF | BENIGN | SAFE, complete | `1d4b3bd3852f4ddf` | all true |
| C92C-T-0001 inert `/Launch` indicator | SECURITY_TEST (not malware) | MALICIOUS, complete; `PDF_LAUNCH_ACTION`, `PDF_Launch_Action` | `5e92bccbd218409d` | all true |
| C92C-T-0002 deliberately malformed PDF | SECURITY_TEST | UNABLE_TO_SCAN, `parser_failure`; the run continued | `328658bf49fe4459` | all true |

**Exports and metadata:**

- **CSV and JSON:** carry `isolation_required`, `isolation`, `isolation_missing`, `complete`,
  `failure_reason`, `request_id` and `ruleset_sha256`.
- **Engine commit:** `b1a6946…`, `working_tree_dirty=False`.
- **Sample bytes:** no raw sample bytes in any export, checked by byte search.
- **Memory:** recorded as `harness_peak_rss_mib=91.3` with `worker_memory_measured=false`.
  **Worker memory was not measured.**

The `MALICIOUS` verdict on the inert indicator is the engine's verdict on a constructed
indicator. It is not independent ground truth and says nothing about detection accuracy.

## 6. Linux tests in the VM

Only `tests/test_worker_linux.py` and `tests/test_evaluation.py` were run in the VM (65 tests),
under the enforcing profile: **61 passed, 4 failed** (`~/c92c3/pytest.final.log`). The rest of
the backend suite was not run in the VM; its results come from Linux CI.

The VM test run is therefore **not** a full pass. None of the four failures is an engine defect.

| Test | Expected | Actual | Classification | Proposed correction (not applied) |
|---|---|---|---|---|
| `test_network_namespace_blocks_connections_when_available` | TCP connect inside the namespace fails with `ENETUNREACH` (101) | Fails earlier with `EACCES` (13): the profile has no `network inet stream` rule | Intended additional restriction | Accept `EACCES` only when the process is confined by an AppArmor profile (label not `unconfined`); keep `ENETUNREACH` for unconfined runs. The route-lookup checks still prove the namespace is unrouted |
| `test_network_verification_detects_the_host_network` | The host namespace has real interfaces and routes, so the checks must fail there | The offline VM's host namespace is itself loopback-only with no routes | Unsupported environment assumption (networked host) | An explicit `FM_EXPECT_OFFLINE_HOST=1` mode that asserts the host namespace is loopback-only and route-free, which is positive offline evidence; the CI assertion is unchanged otherwise |
| `test_diagnostics_read_real_interface_state_in_the_host_namespace` | An up, non-loopback IPv4 interface with ≥1 usable route | 1 interface (`lo`), 0 usable routes | Unsupported environment assumption | In the same offline mode, assert exactly `lo` (`ARPHRD_LOOPBACK`, 772) and 0 routes, still exercising the ioctl parsing |
| `test_capabilities_are_dropped_in_the_kernel_and_cannot_be_regained` | First step: `lo` can be reconfigured *before* the drop (`ok`), proving the capability existed | `EPERM`; `net_admin` is denied by the profile before the drop. All 11 later assertions hold (Section 4) | Intended additional restriction | Accept `EPERM` for that precondition only when AppArmor-confined, keeping every later assertion unchanged. The successful `setpcap`-dependent drop already shows capabilities were held |

The tests were not modified, skipped or removed. The corrections above need separate approval
before they are applied.

## 7. Policy review (no changes made)

**Essential for the strict harness and worker:**

- `userns`
- `capability setpcap`: drop the bounding set and lock the securebits
- `capability sys_admin`: create the network namespace inside the new user namespace
- The interpreter (`rix`) and read/map access to `/opt/filesmagic/**`
- Read access to the repository, manifest and samples; read/write to `~/fm-eval/results`
- `/proc/<pid>/net/*`, own `status`, `fd/`, `cgroup`, and `cpu.max`
- `inet`/`inet6` datagram, `netlink raw`, `unix stream` sockets
- Signals within the profile
- `git` plus its configuration files, for provenance

**Test or development only** (candidates to remove for a study-only profile, after re-validation):

- `~/c92c/**` (validation scripts)
- `/usr/bin/sleep` (process-group test helper)
- `/usr/share/terminfo/**` (pytest output)
- Own `/proc/<pid>/stat` (process-cleanup test)
- `/etc/passwd` and `/etc/nsswitch.conf` (pytest temporary directories)
- `/tmp/**` with write and lock (pytest temporary files and output capture). Narrow it to
  `/tmp/pytest-of-*/**` if tests stay, or remove it for harness-only runs.

Some of these rules were derived from code paths rather than proven necessary one by one, because
the complain-mode log was incomplete. Each removal must be re-validated in enforce mode.

**`sys_admin`:** it can't be limited to one namespace in AppArmor. The process holds no
capabilities in the host user namespace, so it takes effect only in namespaces the worker creates,
and only until `drop_capabilities()`. There are no `mount`, `pivot_root` or `ptrace` rules.

**Residual risks:**

1. **Shared identity.** The harness, its workers and the tests share one profile and one guest user
   (uid 1000).
   - **Order of controls** (`app/worker.py`, `main()`). The worker applies its controls before it
     reads the document:
     1. user and network namespace, verified;
     2. capability drop;
     3. scanner warm-up on empty input;
     4. resource limits;
     5. Python audit hook;
     6. the strict-mode check.

     Only then does it read the document from stdin and run the parsers. Parsing therefore never
     happens before isolation is established.
   - **What remains open to an exploit.** A native-code exploit in a parser would run with
     whatever these controls leave in place: no network, no capabilities and limited resources,
     but the same guest user and the same AppArmor profile as the harness.
   - **What that allows.** It could read every path the profile allows, including all samples.
     It could also delete, rename or truncate files, and create empty files, under
     `~/fm-eval/results` and `/tmp`. The audit hook doesn't constrain native code.
   - **Proposed hardening**, which needs an engine code change: run the worker under a separate
     child profile with no write permissions and no sample access beyond its own input, for
     example by starting it from a distinct interpreter path.
2. **Filesystem write permissions.** The profile grants write access to `~/fm-eval/results/**`
   and to `/tmp/**` (with locks) for the whole profile, workers included.
   - **What `RLIMIT_FSIZE=0` does.** It is a resource limit: the kernel refuses any write that
     would extend a regular file beyond 0 bytes. The write fails with `EFBIG`; CPython ignores
     `SIGXFSZ`.
   - **What it does not do.** It does not stop:
     - deleting, renaming or truncating files;
     - creating empty files or directories;
     - overwriting bytes inside an existing file's current size;
     - writing to pipes or sockets (the worker returns its report over a stdout pipe).

     It is not a filesystem access-control boundary. Access is decided by the AppArmor profile and
     ordinary Unix permissions.
   - **The audit hook** blocks Python-level opens for writing, but not native code. The shared
     writable directories therefore remain exposed to the operations above.
3. **`CAP_SYS_ADMIN` before the drop.** Between `unshare()` and `drop_capabilities()`, the worker
   holds `CAP_SYS_ADMIN` and `CAP_SETPCAP` inside its own new namespaces. The profile denies every
   other capability and grants no `mount`, `pivot_root` or `ptrace` rules. The window is short and
   happens before the document is read, but it is not zero.
4. **Shared kernel.** The guest kernel is shared, and kernel exploits are out of scope.
5. **VM boundary.** The VM is not an absolute security boundary: VirtualBox runs under the Windows
   hypervisor, and hypervisor escapes are out of scope. The host shares no folders, clipboard or
   USB with it.
6. **Path-based attachment.** Any local user can invoke the dedicated interpreter and receive the
   profile's limited permissions. Only the researcher uses this VM.

## 8. Leftover files (metadata only; nothing deleted)

| Item | What it is | Recommendation |
|---|---|---|
| `/var/crash/_opt_filesmagic_python_cpython-3.11.18-linux-x86_64-gnu_bin_python3.11.1000.crash` (1.87 MB, owned by the guest user, group `whoopsie`, mode 640) | Ubuntu crash report from the deliberate `tests.fake_worker segv` test (`ProblemType: Crash`, `SIGSEGV`, `ProcCmdline: /opt/filesmagic/venv/bin/python -B -m tests.fake_worker segv`); rewritten by each run of that test | Delete. It holds a core dump of a test process, with no sample data |
| `~/c92c.failed-transfer/` (`filesmagic-eval-python.complain` 1,166 B, `aa_summary.py` 1,224 B) | Partial extraction from the first transfer, which failed its hash check | Delete. Superseded by the verified copies in `~/c92c` |
| `~/fm-venv/` (94 MB, user-owned 775) | The Phase C9.2B environment; points at the user-writable uv interpreter, which runs **unconfined** | Delete it, and optionally the user-owned uv interpreter, so nothing unconfined can be used by mistake |

## 9. Evidence inside the VM (metadata only)

| Location | Contents |
|---|---|
| `~/c92c/` | Complain-mode run: `aa.allowed.txt`, `probe.complain.json`, `eval.complain.log`, `pytest.complain.log`, `verify_interp.out` |
| `~/c92c2/` | Enforce runs 1 and 2: `aa.denied1.txt`, `aa.denied2.txt`, `probe.enforce*.json`, `eval.enforce*.log`, `pytest.enforce*.log` |
| `~/c92c3/` | Final: `probe.final.json`, `evidence.final.txt`, `evidence.after-reboot.txt`, `eval.final.log`, `eval.after-reboot.log`, `pytest.final.log`, `aa.denied.final.txt`, `cap_probe_full.c92d.txt` |
| `~/fm-eval/results/` | `complain-run`, `enforce-run1` (aborted preflight), `enforce-run2`, `c92c-final`, `c92c-after-reboot`; each with `run_status.json` and, when scanning ran, `per_sample.csv/json` and `summary.json/md` |
| `~/c92b/` | Phase C9.2B installation logs (`apt.log`, `pip.log`, `checks.txt`) |

These files have not been exported from the VM. The procedure for bringing research samples into
the offline VM and exporting metadata-only results has **not been finalized**, and no transfer
mechanism has been implemented. It is an outstanding requirement
([research-readiness-summary.md](research-readiness-summary.md), Section 6, item 7). The VM stays
without network, shared folders, USB and clipboard.

The setup files used during Phases C9.2C and C9.2D were the operator's own scripts and the
AppArmor profile. They contained no samples. They were typed into the guest and verified by
SHA-256; that was not a sample-transfer procedure.

## 10. VM state and snapshots

- **State:** powered off since 2026-10-27 16:35:36 UTC; all adapters `none`.
- **Snapshots:** five, all preserved:

| Snapshot | UUID | Taken (UTC) |
|---|---|---|
| Clean Ubuntu 24.04 - Pre Security Engine | `adebe1c4-248a-4ffb-9b12-907cb1f55bde` | 2026-10-08 02:46 |
| Pre-C9.2 - Existing State Preserved - Unverified (never booted) | `b660f28a-b6f4-4659-b073-b42385d1d071` | 2026-10-27 04:41 |
| C9.2B - Offline Inspected Baseline - Before Software Setup | `fc1aec94-c62b-476d-baf4-2da24f62b720` | 2026-10-27 14:52 |
| C9.2B - Software Installed - Offline | `58e9f6da-b502-4c7e-8af0-acdf23fb3140` | 2026-10-27 15:44 |
| **C9.2C - Strict Isolation Validated - Offline** | `36c2d7f6-decc-49fd-91a4-434ff0aa02e6` | 2026-10-27 16:24 |

The C9.2D inspection boot added only logs and `cap_probe_full.c92d.txt` to the current state on
top of the validated snapshot, which is itself unchanged.

## Appendix A: enforcing profile (`/etc/apparmor.d/filesmagic-eval-python`)

```
abi <abi/4.0>,
include <tunables/global>

profile filesmagic-eval-python /opt/filesmagic/python/cpython-3.11.18-linux-x86_64-gnu/bin/python3.11 {
  include <abstractions/base>
  userns,
  capability setpcap,
  capability sys_admin,
  /opt/filesmagic/python/cpython-3.11.18-linux-x86_64-gnu/bin/python3.11 rix,
  /opt/filesmagic/python/cpython-3.11.18-linux-x86_64-gnu/** r,
  /opt/filesmagic/python/cpython-3.11.18-linux-x86_64-gnu/**.so* mr,
  /opt/filesmagic/venv/** r,
  /opt/filesmagic/venv/**.so* mr,
  owner @{HOME}/filesmagic-security-engine/ r,
  owner @{HOME}/filesmagic-security-engine/** r,
  owner @{HOME}/c92c/ r,
  owner @{HOME}/c92c/** r,
  owner @{HOME}/fm-eval/ r,
  owner @{HOME}/fm-eval/manifest.csv r,
  owner @{HOME}/fm-eval/samples/ r,
  owner @{HOME}/fm-eval/samples/** r,
  owner @{HOME}/fm-eval/results/ rw,
  owner @{HOME}/fm-eval/results/** rw,
  owner /tmp/ r,
  owner /tmp/** rwk,
  @{PROC}/@{pid}/net/{route,ipv6_route,if_inet6,dev} r,
  owner @{PROC}/@{pid}/status r,
  owner @{PROC}/@{pid}/attr/{current,apparmor/current} r,
  owner @{PROC}/@{pid}/fd/ r,
  owner @{PROC}/@{pid}/stat r,
  owner @{PROC}/@{pid}/cgroup r,
  /sys/fs/cgroup/**/cpu.max r,
  /etc/nsswitch.conf r,
  /etc/passwd r,
  /usr/share/terminfo/** r,
  network inet dgram,
  network inet6 dgram,
  network netlink raw,
  network unix stream,
  signal (send, receive) peer=filesmagic-eval-python,
  /usr/bin/sleep rix,
  /usr/bin/git rix,
  /etc/gitconfig r,
  owner @{HOME}/.gitconfig r,
  owner @{HOME}/.config/git/** r,
}
```

The installed file also contains a comment justifying each rule. This listing omits the comments;
the authoritative identifier is the SHA-256 in Section 3.
