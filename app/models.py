"""Shared data models used by the API, the scanners, and the decision engine."""

from enum import Enum
from typing import Annotated, Literal

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
    scanner: str = Field(description="Scanner that produced the finding, e.g. 'yara-x'.")
    category: str = Field(description="Kind of finding, e.g. 'malware', 'macro', 'pdf-javascript'.")
    severity: Severity
    description: str
    rule_id: str | None = Field(default=None, description="Signature or rule name, if any.")


class ScannerStatus(BaseModel):
    name: str = Field(max_length=40)
    status: Literal["completed", "not_applicable", "failed"]
    error: str | None = Field(default=None, max_length=300, description="Sanitised reason a scanner failed.")
    error_kind: Literal["malformed_input", "invalid_structure", "unexpected", "worker"] | None = Field(
        default=None, description="malformed_input/invalid_structure: expected for hostile or broken files; "
        "unexpected: a possible scanner bug; worker: the isolated worker crashed or timed out.")
    error_type: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,79}$")


class WorkerReport(BaseModel):
    """What the isolated scan worker sends back. Treated as untrusted input by the API."""

    scanners: list[ScannerStatus] = Field(max_length=20)
    findings: list[Finding] = Field(max_length=500)
    isolation: dict[str, bool] = Field(default_factory=dict, max_length=16)
    # Code locations only (file:line:function), for unexpected failures; logged, never returned.
    traces: dict[str, Annotated[str, Field(max_length=1000, pattern=r"^[A-Za-z0-9_.:<> -]*$")]] = Field(default_factory=dict, max_length=20)


class ScanResult(BaseModel):
    request_id: str = Field(default="", description="Correlates this result with the engine's log lines.")
    filename: str
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    message: str
    sha256: str = ""
    size_bytes: int = 0
    detected_format: str = Field(default="unknown", description="From magic bytes only: pdf, ole2, zip, rtf, unknown.")
    scanners: list[ScannerStatus] = Field(default_factory=list)
    complete: bool = Field(default=False, description="Every applicable scanner completed its analysis.")
    duration_ms: float = 0
    versions: dict[str, str] = Field(default_factory=dict)
    isolation_required: bool = Field(default=False, description="Configured: SECURITY_ENGINE_REQUIRE_ISOLATION=1, "
                                     "so the worker refuses to scan unless every isolation value is true.")
    isolation: dict[str, bool] = Field(default_factory=dict, description="Reported by the worker: controls applied "
                                       "(e.g. network_namespace) and independently verified (network_verified, net_*).")
