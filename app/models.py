"""Shared data models used by the API, the scanners, and the decision engine."""

from enum import Enum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


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


_KERNEL_NAME = r"^[A-Za-z_][A-Za-z0-9_]{0,39}$"  # exception types and errno names, e.g. ENODEV


class InterfaceDiagnostics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=-1, le=2**31 - 1)
    name: str = Field(pattern=r"^[A-Za-z0-9_.:@?-]{1,15}$")
    up: bool | None = None
    running: bool | None = None
    loopback: bool | None = None
    link_type: int | None = Field(default=None, ge=0, le=65535, description="ARPHRD_* value")
    ipv4_address: bool | None = None
    ipv6_addresses: int = Field(default=0, ge=0, le=10000)
    usable_routes_v4: int | None = Field(default=None, ge=0, le=100000)
    usable_routes_v6: int | None = Field(default=None, ge=0, le=100000)
    error: str | None = Field(default=None, pattern=_KERNEL_NAME)


class NetworkDiagnostics(BaseModel):
    """Staging-only description of the worker's network namespace. Logged, never returned."""

    model_config = ConfigDict(extra="forbid")

    interface_count: int | None = Field(default=None, ge=0, le=100000)
    interfaces: list[InterfaceDiagnostics] = Field(default_factory=list, max_length=16)
    enumeration_error: str | None = Field(default=None, pattern=_KERNEL_NAME)
    enumeration_errno: str | None = Field(default=None, pattern=_KERNEL_NAME)
    usable_routes_v4: int | None = Field(default=None, ge=0, le=100000)
    usable_routes_v6: int | None = Field(default=None, ge=0, le=100000)
    proc_error: str | None = Field(default=None, pattern=_KERNEL_NAME)
    collection_error: str | None = Field(default=None, pattern=_KERNEL_NAME)


class WorkerReport(BaseModel):
    """What the isolated scan worker sends back. Treated as untrusted input by the API."""

    scanners: list[ScannerStatus] = Field(max_length=20)
    findings: list[Finding] = Field(max_length=500)
    isolation: dict[str, bool] = Field(default_factory=dict, max_length=16)
    # Code locations only (file:line:function), for unexpected failures; logged, never returned.
    traces: dict[str, Annotated[str, Field(max_length=1000, pattern=r"^[A-Za-z0-9_.:<> -]*$")]] = Field(default_factory=dict, max_length=20)
    diagnostics: NetworkDiagnostics | None = None  # SECURITY_ENGINE_NET_DIAGNOSTICS=1 only; logged, never returned


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
                                     "so the worker refuses to scan unless every required isolation value is true.")
    isolation: dict[str, bool] = Field(default_factory=dict, description="Reported by the worker: controls applied "
                                       "(e.g. network_namespace) and independently verified (network_verified, net_*). "
                                       "net_loopback_only / net_fallback_tunnel_inert describe the interfaces found; "
                                       "exactly one is true when net_interfaces_safe is.")
    isolation_missing: list[str] = Field(default_factory=list, description="Required isolation values that are not "
                                         "true. Strict mode analyses a file only when this is empty.")
