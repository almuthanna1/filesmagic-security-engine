# In-VM validation of the benign real-VBA macro document at `47fb891` (2026-11-09)

Offline VM `FilesMagic-securityLAB`, confined interpreter `filesmagic-eval-python (enforce)`,
strict isolation. **Inert and benign only; no genuine malware.** This completes, inside the VM,
the real-oletools-extraction check that [evaluation/vba_fixture.py](../../../evaluation/vba_fixture.py)
first proved on the host. Tool and fixture: commit `47fb891`.

## Outcome

| Step | Result |
|---|---|
| ISO swap (host, powered off) | only IDE 0-0 changed, 15126e8 → 47fb891 ISO (`b8ce7ce9…4378`); isolation settings unchanged |
| Disc integrity (`single-47fb891-logs/disc-and-install.txt`) | `sha256sum -c` 7/7 OK; whole disc `/dev/sr0` = host ISO `b8ce7ce9…4378`; commit `47fb891`; no EICAR |
| Install | detached checkout at `47fb891`, clean tree; `app/` `c50b66c1…` and `requirements.txt` `5089f11d…` = frozen release; disc unmounted |
| `guest_checks.sh` (`single-47fb891-logs/guest-checks.txt`) | all controls PASS, 0 STOP |
| `single_sample` on the macro doc from `~/fm-eval/samples/`, 5 trials/engine (`single-macro-47fb891/`) | **completed · PASS**, 22/22 pre-registered checks held, no defects |

### Result

Both engines **SUSPICIOUS**, deterministic over 5 trials, `isolation_missing` empty, 3 AppArmor
denials (the usual `git`/`uname`), **0 on the samples path**.

| Engine | Findings |
|---|---|
| reference | `yara-x:OLE_Office_VBA_Macros:MEDIUM`, `office:OFFICE_MACROS_PRESENT:LOW`, `office:OFFICE_MACRO_AUTOEXEC:MEDIUM` |
| unified | the same, plus `vba-chains:ENGINE_VBA_NO_CALL_PATH:INFO` |

`OFFICE_MACRO_AUTOEXEC` ("runs automatically via: AutoOpen") and `ENGINE_VBA_NO_CALL_PATH` are
produced by the **real** oletools extraction and the call-graph on genuine source — never
`OFFICE_VBA_UNPARSED`. The auto-execution macro is detected; with no dangerous capability the
document is correctly **not** convicted (SUSPICIOUS, not MALICIOUS). The report is JavaScript-free
with no external reference; the standard keyword "AutoOpen" is shown (not an indicator), while URLs,
UNC paths and quoted literals are withheld by the redactor (unit-tested separately).

The macro document bytes are not committed: `single_sample --write-inert` rebuilds the fixture
deterministically (`inert-benign-macro-doc.bin` = `f1cd6d6d…157b1`). All 9 files here match
`SHA256SUMS-macro.txt` taken in the guest (`0501b8a9…e3b9`).
