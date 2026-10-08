"""Shared data models used by the API, the scanners, and the decision engine."""

from enum import Enum

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNABLE_TO_SCAN = "UNABLE_TO_SCAN"


class Severity(str, Enum):
    """How serious a single finding is. INFO findings never change the verdict."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    scanner: str = Field(description="Scanner that produced the finding, e.g. 'clamav'.")
    category: str = Field(description="Kind of finding, e.g. 'malware', 'macro', 'pdf-javascript'.")
    severity: Severity
    description: str
    rule_id: str | None = Field(default=None, description="Signature or rule name, if any.")


class ScanResult(BaseModel):
    filename: str
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    message: str
