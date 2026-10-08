"""Deterministic verdict rules. Combines findings from all scanners into one verdict.

Rules, applied in order:
1. Any HIGH or CRITICAL finding           -> MALICIOUS
2. Any LOW or MEDIUM finding              -> SUSPICIOUS
3. No scanner ran, or any scanner failed  -> UNABLE_TO_SCAN
4. Otherwise (all scanners ran clean)     -> SAFE

Evidence wins over failures: a MALICIOUS finding from one scanner still counts
even if another scanner crashed. SAFE needs positive evidence that every
configured scanner actually analysed the file.
"""

from app.models import Finding, Severity, Verdict


def decide(findings: list[Finding], scanners_run: int, scanners_failed: int = 0) -> Verdict:
    severities = {f.severity for f in findings}
    if severities & {Severity.HIGH, Severity.CRITICAL}:
        return Verdict.MALICIOUS
    if severities & {Severity.LOW, Severity.MEDIUM}:
        return Verdict.SUSPICIOUS
    if scanners_run == 0 or scanners_failed > 0:
        return Verdict.UNABLE_TO_SCAN
    return Verdict.SAFE
