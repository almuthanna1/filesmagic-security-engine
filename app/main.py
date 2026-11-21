import asyncio
import hashlib
import logging
import os
import re
import subprocess
import time
import uuid
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import auth, receipts, worker
from app import engine as unified_engine
from app.decision import classify, decide
from app.models import ScannerStatus, ScanResult, Verdict, WorkerReport

logger = logging.getLogger(__name__)
# uvicorn only configures its own loggers; without this the per-scan audit lines are dropped.
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(name)s: %(message)s")

# Origins of the Security Lab frontend allowed to call the API from a browser.
DEFAULT_CORS_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"

# Largest file /scan accepts. Bounds memory per request on a small instance; every
# scanner receives the whole file, so this also bounds scanner work.
MAX_UPLOAD_BYTES = worker.MAX_INPUT_BYTES
UPLOAD_TOO_LARGE = f"File is too large. The maximum upload size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
UPLOAD_TIMEOUT_SECONDS = 60
# Scans running at once (each one is a worker process holding up to 10 MB of input).
MAX_CONCURRENT_SCANS = int(os.environ.get("SECURITY_ENGINE_MAX_CONCURRENT_SCANS", "1"))

# Default runner: one isolated worker process per scan. Tests swap in an in-process runner.
run_scan = worker.run
_active_scans = 0

# One engine: the unified Security Engine (app.engine). The reference runtime (YARA-X and
# olevba's heuristics, app.scanners' original roster) was retired by the custom detection
# rebuild (docs/custom-detection-rebuild); a request for it is refused with ENGINE_RETIRED,
# never answered by another engine.
DEFAULT_ENGINE = "unified"
RETIRED_ENGINES = {"reference"}


def engine_scanners(engine: str = DEFAULT_ENGINE) -> list[str]:
    """Names the worker must report, read at call time (tests replace the roster)."""
    return [s.name for s in unified_engine.SCANNERS]


def engine_ready(engine: str = DEFAULT_ENGINE) -> bool:
    """Every scanner loaded in this process (the worker loads the same code and rules)."""
    return all(getattr(s, "ready", True) for s in unified_engine.SCANNERS)


class ApiError(HTTPException):
    """An HTTP error with a stable machine-readable `code` next to the human `detail`."""

    def __init__(self, status_code: int, code: str, detail: str, headers: dict | None = None):
        super().__init__(status_code=status_code, detail=detail, headers=headers)
        self.code = code


def available_engines() -> list[str]:
    return [DEFAULT_ENGINE]


def source_commit() -> str:
    """The engine's source commit: SECURITY_ENGINE_COMMIT or Render's RENDER_GIT_COMMIT when set
    (deployments have no .git), else `git rev-parse HEAD` in a checkout, else "unknown"."""
    commit = os.environ.get("SECURITY_ENGINE_COMMIT") or os.environ.get("RENDER_GIT_COMMIT")
    if commit:
        return commit[:40]
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent.parent,
                             capture_output=True, text=True, timeout=5)
        return out.stdout.strip()[:40] if out.returncode == 0 and out.stdout.strip() else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


# Fixed explanations for expected scanner failures (logged; nothing attacker-supplied).
FAILURE_REASONS = {
    ("pdf", "malformed_input"): "PDF is malformed or truncated; its structure could not be read",
    ("pdf", "invalid_structure"): "PDF structure is invalid or exceeds analysis limits",
    ("office", "malformed_input"): "Office ZIP/XML structure is malformed or unreadable",
    ("office", "invalid_structure"): "Office document structure is invalid or exceeds analysis limits",
    ("custom", "malformed_input"): "Office ZIP container or XML part is malformed; the custom detector could not read it",
    ("custom", "invalid_structure"): "Document syntax is invalid or exceeds the custom detector's analysis limits",
}


def parse_cors_origins(value: str) -> list[str]:
    """Parse a comma-separated origin allow-list. Wildcards are rejected on purpose."""
    origins = [o.strip().rstrip("/") for o in value.split(",") if o.strip()]
    if "*" in origins:
        raise ValueError("SECURITY_ENGINE_CORS_ORIGINS must list explicit origins, not '*'.")
    return origins


app = FastAPI(
    title="FilesMagic Security Engine",
    description="Pre-conversion file security analysis service for FilesMagic.",
    version="0.2.0",
)

# Parsing libraries whose versions the receipt records (none decides a finding). Both ruleset keys
# stay in the receipt contract; since the rebuild there is one ruleset, so they carry the same hash.
PARSERS = ("oletools", "olefile", "pypdf")
VERSIONS = {"engine": app.version, "commit": source_commit(), "ruleset_sha256": unified_engine.ruleset_hash(),
            "engine_ruleset_sha256": unified_engine.ruleset_hash()} | {pkg: metadata.version(pkg) for pkg in PARSERS}

@app.exception_handler(ApiError)
async def scan_error(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse({"detail": exc.detail, "code": exc.code}, status_code=exc.status_code, headers=exc.headers)


app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(os.environ.get("SECURITY_ENGINE_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)),
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Filename"],
    max_age=600,
)


@app.get("/health")
async def health():
    # "ok" means the API process is up. scanners_ready counts registered scanners that
    # loaded successfully (e.g. signature rules validated); a scanner without a `ready`
    # attribute is counted as ready. A not-ready scanner makes /scan UNABLE_TO_SCAN.
    return {
        "status": "ok",
        "service": "filesmagic-security-engine",
        "scanners_registered": len(unified_engine.SCANNERS),
        "scanners_ready": sum(1 for s in unified_engine.SCANNERS if getattr(s, "ready", True)),
        "auth_configured": auth.PUBLIC_KEY is not None,
        "engines": available_engines(),
        "default_engine": DEFAULT_ENGINE,
        "commit": VERSIONS["commit"],
        # Integration contract v1: what the Conversion Engine needs before it sends a file.
        "conversion_auth_configured": auth.CONVERSION_PUBLIC_KEY is not None,
        "receipt_key_id": receipts.current_key_id(),
        "isolation_required": worker.REQUIRE_ISOLATION,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "ready_for_conversion": bool(
            auth.CONVERSION_PUBLIC_KEY and receipts.PRIVATE_KEY and worker.REQUIRE_ISOLATION
            and auth.distinct_issuer_keys() and "unified" in available_engines() and engine_ready("unified")),
    }


def client_address(request: Request) -> str:
    # The proxy in front of Render appends the connecting address as the LAST
    # X-Forwarded-For entry; earlier entries are client-supplied and spoofable.
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.rsplit(",", 1)[-1].strip() or (request.client.host if request.client else "unknown")


def detect_format(data: bytes) -> str:
    """Coarse type from magic bytes only (no parsing happens in the API process)."""
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole2"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"{\\rt"):
        return "rtf"
    return "unknown"


def clean_filename(header: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", unquote(header))[:255]


async def read_body(request: Request, limit: int) -> bytes:
    """Read the raw upload into memory, never past `limit` bytes and never to disk."""
    data = bytearray()
    try:
        async with asyncio.timeout(UPLOAD_TIMEOUT_SECONDS):
            async for chunk in request.stream():
                data += chunk
                if len(data) > limit:
                    raise ApiError(413, "UPLOAD_TOO_LARGE", UPLOAD_TOO_LARGE)
    except TimeoutError:
        raise ApiError(408, "UPLOAD_TIMEOUT", "Upload took too long.") from None
    return bytes(data)


# The request body is the raw file (no multipart parsing); the original filename, which is
# informational only, comes percent-encoded in X-Filename. Authorization is checked before a
# single body byte is read.
@app.post("/scan", response_model=ScanResult)
async def scan_file(request: Request) -> ScanResult:
    global _active_scans
    request_id = uuid.uuid4().hex[:16]
    client = client_address(request)
    if auth.too_many_failures(client):
        raise ApiError(429, "RATE_LIMITED", "Too many unauthorized requests. Try again later.",
                        headers={"Retry-After": "60"})
    # Checked before the token, so a refused engine does not use up the single-use token.
    engine = request.query_params.get("engine", DEFAULT_ENGINE)
    if engine in RETIRED_ENGINES:
        raise ApiError(410, "ENGINE_RETIRED", f"The {engine} engine was retired; omit engine or use engine=unified.")
    if engine not in available_engines():
        raise ApiError(400, "ENGINE_UNKNOWN", f"Unknown engine; use one of: {', '.join(available_engines())}.")
    expected = engine_scanners()
    try:
        claims = auth.verify(request.headers.get("authorization", ""))
    except auth.AuthError as e:
        auth.record_failure(client)
        logger.warning("scan rejected request_id=%s code=%s", request_id, e.code)
        raise ApiError(401, e.code, str(e), headers={"WWW-Authenticate": "Bearer"}) from None

    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_UPLOAD_BYTES:
        raise ApiError(413, "UPLOAD_TOO_LARGE", UPLOAD_TOO_LARGE)
    if _active_scans >= MAX_CONCURRENT_SCANS:
        raise ApiError(429, "ENGINE_BUSY", "The engine is busy with another scan. Try again shortly.",
                        headers={"Retry-After": "5"})

    _active_scans += 1
    try:
        data = await read_body(request, MAX_UPLOAD_BYTES)
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 != claims["sha256"] or len(data) != claims["size"]:
            raise ApiError(403, "TOKEN_FILE_MISMATCH", "The uploaded file does not match the scan token.")
        start = time.perf_counter()
        operational = [] if engine_ready() else ["SCANNER_NOT_READY"]
        try:
            report = await run_scan(data, engine=engine)
            # The selected engine's scanners, exactly: a worker that ran the other engine (or lost
            # a scanner) fails the scan rather than answering for an engine that did not run.
            if sorted(s.name for s in report.scanners) != sorted(expected):
                raise worker.WorkerError(f"scan worker reported an unexpected set of scanners for the {engine} engine",
                                         "SCANNER_ROSTER_MISMATCH")
            if not worker.REQUIRE_ISOLATION:
                operational.append("ISOLATION_NOT_ENFORCED")
            elif worker.missing_controls(report.isolation):
                operational.append("ISOLATION_UNVERIFIED")
        except worker.WorkerError as e:
            logger.error("scan worker failure request_id=%s engine=%s code=%s: %s", request_id, engine, e.code, e)
            operational.append(e.code)
            report = WorkerReport(
                scanners=[ScannerStatus(name=name, status="failed", error=str(e), error_kind="worker")
                          for name in expected],
                findings=[],
            )
        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        detected_format = detect_format(data)
    finally:
        _active_scans -= 1
        data = None  # the upload is not kept beyond the scan

    findings = report.findings
    failed = sum(s.status == "failed" for s in report.scanners)
    not_applicable = sum(s.status == "not_applicable" for s in report.scanners)
    # Not-applicable scanners neither count as analysis nor as failure.
    applicable = len(expected) - not_applicable
    coverage_complete = report.coverage_complete
    verdict = decide(findings, scanners_run=applicable, scanners_failed=failed, coverage_complete=coverage_complete)
    coverage_issues = report.coverage_issues
    if applicable == 0:
        operational.append("UNSUPPORTED_FILE_TYPE")
    reasons, authorization, explanation = classify(verdict, report.scanners, coverage_issues, operational)
    isolation_missing = worker.missing_controls(report.isolation)
    isolation_verified = worker.REQUIRE_ISOLATION and not isolation_missing
    complete = applicable > 0 and failed == 0
    # A receipt only for a validated outcome, only to the Conversion Engine, only from the
    # production engine: never with an operational reason (which includes unverified isolation).
    receipt = None
    if claims["issuer"] == "conversion" and isolation_verified and not any(
            r.category == "operational" for r in reasons):
        receipt = receipts.sign({
            "scan_request_id": request_id, "token_jti": claims["jti"],
            "sha256": sha256, "size": claims["size"], "detected_format": detected_format,
            "engine": engine, "engine_version": VERSIONS["engine"], "commit": VERSIONS["commit"],
            "ruleset_sha256": VERSIONS["ruleset_sha256"], "engine_ruleset_sha256": VERSIONS["engine_ruleset_sha256"],
            "scanner_versions": {k: VERSIONS[k] for k in PARSERS},
            "scanners": sorted(expected),
            "verdict": verdict.value, "authorization": authorization,
            "complete": complete, "coverage_complete": coverage_complete, "isolation_verified": isolation_verified,
            "override_eligible": authorization == "consent_required",
            "reason_codes": [r.code for r in reasons], "findings_count": len(findings),
        })

    if not expected:
        message = "No security scanners are configured yet. This file has NOT been security-scanned."
    elif applicable == 0:
        message = "None of the configured scanners supports this file type. This file has NOT been security-scanned."
    elif failed and verdict == Verdict.UNABLE_TO_SCAN:
        message = f"{failed} of {applicable} applicable scanners failed, so the file could not be fully analysed."
    elif not coverage_complete and verdict == Verdict.UNABLE_TO_SCAN:
        message = "Required content coverage is incomplete, so the file could not be fully analysed."
    else:
        message = f"Analysed by {applicable - failed} of {len(expected)} scanners"
        message += f" ({not_applicable} not applicable to this file type)." if not_applicable else "."
        if verdict == Verdict.SAFE:
            message += " No known indicators were found; this is not a guarantee that the file is harmless."

    # Logs carry only controlled values: never file contents, the filename, or scanner error
    # text (which can quote attacker-controlled data). Scanner names were checked against
    # SCANNERS, error kinds/types and traces were validated by the WorkerReport model.
    for s in report.scanners:
        if s.status != "failed" or s.error_kind == "worker":
            continue
        if s.error_kind == "unexpected":
            logger.error("scanner failure request_id=%s scanner=%s kind=unexpected type=%s trace=%s",
                         request_id, s.name, s.error_type, report.traces.get(s.name, "unavailable"))
        else:
            logger.warning("scanner failure request_id=%s scanner=%s kind=%s type=%s reason=%s",
                           request_id, s.name, s.error_kind, s.error_type,
                           FAILURE_REASONS.get((s.name, s.error_kind), "document could not be analysed"))
    if report.diagnostics:  # staging only; validated by the WorkerReport model, never in the response
        logger.warning("network diagnostics request_id=%s %s", request_id,
                       report.diagnostics.model_dump_json(exclude_none=True))
    logger.info("scan request_id=%s engine=%s issuer=%s sha256=%s size=%d verdict=%s authorization=%s reasons=%s "
                "receipt=%s failed=%d duration_ms=%.0f", request_id, engine, claims["issuer"], sha256[:16],
                claims["size"], verdict.value, authorization, ",".join(r.code for r in reasons) or "-",
                "issued" if receipt else "none", failed, duration_ms)
    return ScanResult(
        request_id=request_id,
        engine=engine,
        filename=clean_filename(request.headers.get("x-filename", "")),
        verdict=verdict,
        findings=findings,
        message=message,
        sha256=sha256,
        size_bytes=claims["size"],
        detected_format=detected_format,
        scanners=report.scanners,
        complete=complete,
        coverage_complete=coverage_complete,
        coverage_issues=coverage_issues,
        duration_ms=duration_ms,
        versions=VERSIONS,
        isolation_required=worker.REQUIRE_ISOLATION,
        isolation=report.isolation,
        isolation_missing=isolation_missing,
        isolation_verified=isolation_verified,
        reasons=reasons,
        override_eligible=authorization == "consent_required",
        authorization=authorization,
        explanation=explanation,
        receipt=receipt,
    )
