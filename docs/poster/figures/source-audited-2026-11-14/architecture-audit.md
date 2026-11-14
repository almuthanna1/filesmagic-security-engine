# Architecture audit for poster claims

- `app/main.py:scan_file` authorizes the request, verifies hash/size before scan, invokes `worker.run`, calls `decision.decide`, and returns the result.
- `app/worker.py:run` launches a fresh bounded worker and kills its process group. `main` chooses reference/unified scanner sets; correlation runs only for unified scans.
- Linux controls are implemented in `network_isolation`, `verify_network_isolation`, `drop_capabilities`, `apply_limits`, `_audit_hook`, and `missing_controls`; strict mode refuses analysis when required controls are absent. Frozen sources: `tests/test_worker_linux.py` and `docs/evidence/final-eda2a08-run3/`.
- Reference scanners are YARA-X, PDF, Office, and custom structural analysis. The current unified research engine adds refined signatures, PDF chains, PDF integrity/coverage, VBA, OOXML, Word fields, and correlation.
- Verdict policy: HIGH/CRITICAL -> MALICIOUS; LOW/MEDIUM -> SUSPICIOUS; otherwise scanner failure/no applicable scanner -> UNABLE_TO_SCAN; else SAFE. The production converter gate remains proposed.
- Frozen Nov. 9: 114/114 outcomes and 11/11 checks, not general malware-detection accuracy. Hosted Nov. 14: two selected qpdf rescans at `840a300c`; verdicts/scanner counts/findings/worker-reported isolation were recorded, but raw hosted coverage fields were not exported.
