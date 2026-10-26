import asyncio
import hashlib
import logging
import os
import re
import time
import uuid
from importlib import metadata
from pathlib import Path
from urllib.parse import unquote

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from app import auth, worker
from app.decision import decide
from app.models import ScannerStatus, ScanResult, Verdict, WorkerReport
from app.scanners import SCANNERS
from app.scanners.yarax import RULES_DIR

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


# Fixed explanations for expected scanner failures (logged; nothing attacker-supplied).
FAILURE_REASONS = {
    ("pdf", "malformed_input"): "PDF is malformed or truncated; its structure could not be read",
    ("pdf", "invalid_structure"): "PDF structure is invalid or exceeds analysis limits",
    ("office", "malformed_input"): "Office ZIP/XML structure is malformed or unreadable",
    ("office", "invalid_structure"): "Office document structure is invalid or exceeds analysis limits",
}


def parse_cors_origins(value: str) -> list[str]:
    """Parse a comma-separated origin allow-list. Wildcards are rejected on purpose."""
    origins = [o.strip().rstrip("/") for o in value.split(",") if o.strip()]
    if "*" in origins:
        raise ValueError("SECURITY_ENGINE_CORS_ORIGINS must list explicit origins, not '*'.")
    return origins


def ruleset_hash(rules_dir: Path = RULES_DIR) -> str:
    """Version identifier of the rule set. Line endings are normalised (CRLF/CR -> LF) so a
    Windows checkout and the Linux image report the same hash for identical rules; the rules
    YARA-X compiles are not changed by this."""
    h = hashlib.sha256()
    for path in sorted(rules_dir.glob("*.yar")):
        text = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        h.update(path.name.encode() + b"\0" + text)
    return h.hexdigest()


app = FastAPI(
    title="FilesMagic Security Engine",
    description="Pre-conversion file security analysis service for FilesMagic.",
    version="0.2.0",
)

VERSIONS = {"engine": app.version, "ruleset_sha256": ruleset_hash()} | {
    pkg: metadata.version(pkg) for pkg in ("yara-x", "oletools", "olefile", "pypdf")
}

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
    # loaded successfully (e.g. YARA-X rules compiled); a scanner without a `ready`
    # attribute is counted as ready. A not-ready scanner makes /scan UNABLE_TO_SCAN.
    return {
        "status": "ok",
        "service": "filesmagic-security-engine",
        "scanners_registered": len(SCANNERS),
        "scanners_ready": sum(1 for s in SCANNERS if getattr(s, "ready", True)),
        "auth_configured": auth.PUBLIC_KEY is not None,
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
                    raise HTTPException(status_code=413, detail=UPLOAD_TOO_LARGE)
    except TimeoutError:
        raise HTTPException(status_code=408, detail="Upload took too long.") from None
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
        raise HTTPException(status_code=429, detail="Too many unauthorized requests. Try again later.",
                            headers={"Retry-After": "60"})
    try:
        claims = auth.verify(request.headers.get("authorization", ""))
    except auth.AuthError as e:
        auth.record_failure(client)
        logger.warning("scan rejected request_id=%s: %s", request_id, e)
        raise HTTPException(status_code=401, detail=str(e), headers={"WWW-Authenticate": "Bearer"}) from None

    length = request.headers.get("content-length", "")
    if length.isdigit() and int(length) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=UPLOAD_TOO_LARGE)
    if _active_scans >= MAX_CONCURRENT_SCANS:
        raise HTTPException(status_code=429, detail="The engine is busy with another scan. Try again shortly.",
                            headers={"Retry-After": "5"})

    _active_scans += 1
    try:
        data = await read_body(request, MAX_UPLOAD_BYTES)
        sha256 = hashlib.sha256(data).hexdigest()
        if sha256 != claims["sha256"] or len(data) != claims["size"]:
            raise HTTPException(status_code=403, detail="The uploaded file does not match the scan token.")
        start = time.perf_counter()
        try:
            report = await run_scan(data)
            if sorted(s.name for s in report.scanners) != sorted(s.name for s in SCANNERS):
                raise worker.WorkerError("scan worker reported an unexpected set of scanners")
        except worker.WorkerError as e:
            logger.error("scan worker failure request_id=%s: %s", request_id, e)  # message is the engine's own
            report = WorkerReport(
                scanners=[ScannerStatus(name=s.name, status="failed", error=str(e), error_kind="worker")
                          for s in SCANNERS],
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
    applicable = len(SCANNERS) - not_applicable
    verdict = decide(findings, scanners_run=applicable, scanners_failed=failed)

    if not SCANNERS:
        message = "No security scanners are configured yet. This file has NOT been security-scanned."
    elif applicable == 0:
        message = "None of the configured scanners supports this file type. This file has NOT been security-scanned."
    elif failed and verdict == Verdict.UNABLE_TO_SCAN:
        message = f"{failed} of {applicable} applicable scanners failed, so the file could not be fully analysed."
    else:
        message = f"Analysed by {applicable - failed} of {len(SCANNERS)} scanners"
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
    logger.info("scan request_id=%s sha256=%s size=%d verdict=%s failed=%d duration_ms=%.0f",
                request_id, sha256[:16], claims["size"], verdict.value, failed, duration_ms)
    return ScanResult(
        request_id=request_id,
        filename=clean_filename(request.headers.get("x-filename", "")),
        verdict=verdict,
        findings=findings,
        message=message,
        sha256=sha256,
        size_bytes=claims["size"],
        detected_format=detected_format,
        scanners=report.scanners,
        complete=applicable > 0 and failed == 0,
        duration_ms=duration_ms,
        versions=VERSIONS,
        isolation_required=worker.REQUIRE_ISOLATION,
        isolation=report.isolation,
        isolation_missing=worker.missing_controls(report.isolation),
    )
