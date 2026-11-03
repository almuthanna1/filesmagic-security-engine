"""Indicator results and evidence for the custom detector.

Every indicator returns Signals: the rule that fired, what it found, concrete evidence and
where in the document. A Signal becomes exactly one Finding attributed to the custom scanner,
so the existing decision engine applies the same severity policy as for every other scanner.
Severity is fixed per rule and stated with the rule; nothing is escalated by adding up
numerical weights. (A composite view across indicators waits until there is more than one.)
"""

import re
from dataclasses import dataclass

from app.models import Finding, Severity

SCANNER = "custom"
MAX_ITEMS = 3  # evidence entries and locations shown per finding
NOT_PROOF = " This is a structural indicator, not proof that the file is malicious."


def clean(text: str, limit: int = 80) -> str:
    """Attacker-controlled text made safe and short enough to show in a finding."""
    text = re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def listing(items: list[str]) -> str:
    shown = "; ".join(items[:MAX_ITEMS])
    return shown + (f"; and {len(items) - MAX_ITEMS} more" if len(items) > MAX_ITEMS else "")


@dataclass(frozen=True)
class Signal:
    rule_id: str
    category: str
    severity: Severity
    summary: str  # what was found, hedged: never claims the file is malware
    evidence: tuple[str, ...]  # already cleaned, most significant first
    locations: tuple[str, ...] = ()  # where in the document, when known

    def to_finding(self) -> Finding:
        description = f"{self.summary} Evidence: {listing(list(self.evidence))}."
        if self.locations:
            description += f" Location: {listing(list(self.locations))}."
        if self.severity != Severity.INFO:
            description += NOT_PROOF
        return Finding(scanner=SCANNER, category=self.category, severity=self.severity,
                       description=description, rule_id=self.rule_id)
