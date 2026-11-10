# In-VM AES extractor test, 7-Zip 26.06 `7zzs` (2026-11-10 04:27Z): passed

Offline VM `FilesMagic-securityLAB`, booted from **"Pre-sample baseline - containment configured
2026-11-09"** and reverted to it afterwards. **Benign files only: no genuine malware was acquired,
transferred, extracted or scanned.** The frozen engine was not run or changed.
Details of the extractor and the test archive: [emotet-pilot-run-log.md §2b](../../emotet-pilot-run-log.md).

| Step | Result |
|---|---|
| Test disc `fm-aes-test.iso` (`7zzs`, `fm-aes-test.zip`, `SHA256SUMS`) | host SHA-256 `a4e6b1c6…0082` (`host/fm-aes-test.iso.sha256`); **whole `/dev/sr0` hashed in the guest = the host ISO**; `sha256sum -c` 2/2 OK |
| VM settings, attach (`host/vm-settings-attach-diff.txt`) | VM powered off; only the `IDE-0-0` optical keys changed |
| `noexec` sample mount | `tmpfs rw,nosuid,nodev,noexec,size=64m,mode=700,uid=1000,gid=1000` on `~/fm-eval/samples/malicious`; **a copied executable was refused (`Permission denied`, 126)** |
| `7zzs` installed to `~/fm-eval/bin/` | SHA-256 = pinned `0b58a64e…8c1f`; reports `7-Zip (z) 26.06 (x64)` |
| Listing | both entries `Encrypted = +`, `AES-256 Store` and `AES-256 Deflate` |
| Wrong password | exit **2**, `ERROR: Wrong password` for both entries. **It leaves two empty (0-byte) placeholder files** in the output directory |
| Correct password (`infected`) | exit 0, "Everything is Ok"; **both extracted files match their expected SHA-256** |
| `guest_checks.sh` | every control PASS, `RESULT all controls present` (INFO: the test disc was mounted at the time) |
| Shutdown + revert (`host/vm-settings-revert-diff.txt`) | ACPI shutdown in 10 s; `snapshot restorecurrent`; vs the pre-test settings only the state time and the fresh differencing disk differ; `IDE-0-0` emptydrive, NICs `none`, clipboard/drag-drop/USB/VRDE off, 7 snapshots (`host/vm-isolation-keys-after-revert.txt`) |

**Consequence for the session.** A wrong password does not leave the output empty: the
placeholders exist. The session therefore relies on the **exit code and the document's SHA-256**,
never on a file merely existing — the planned `e50c941c…` check catches it.

`guest/aes-test.log` (`604fa9ca…3a75`) and `guest/guest-checks.txt` (`53bb2b72…2834`) were hashed in
the guest and match on the host after `guestcontrol copyfrom`.
