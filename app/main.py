import logging
import os
from xml.etree.ElementTree import ParseError as XMLParseError
from zipfile import BadZipFile

from defusedxml.common import DefusedXmlException
from pypdf.errors import PdfReadError

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.decision import decide
from app.models import Finding, ScanResult, Verdict
from app.scanners import SCANNERS
from app.scanners.office import OfficeScanError
from app.scanners.pdf import PdfScanError

logger = logging.getLogger(__name__)

# Origins of the Security Lab frontend allowed to call the API from a browser.
DEFAULT_CORS_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"

# Largest file /scan accepts. Bounds memory per request on a small instance; every
# scanner receives the whole file, so this also bounds scanner work.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# Room for multipart boundaries and part headers on top of the file itself.
MULTIPART_OVERHEAD_BYTES = 64 * 1024
UPLOAD_TOO_LARGE = f"File is too large. The maximum upload size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."


def parse_cors_origins(value: str) -> list[str]:
    """Parse a comma-separated origin allow-list. Wildcards are rejected on purpose."""
    origins = [o.strip().rstrip("/") for o in value.split(",") if o.strip()]
    if "*" in origins:
        raise ValueError("SECURITY_ENGINE_CORS_ORIGINS must list explicit origins, not '*'.")
    return origins


app = FastAPI(
    title="FilesMagic Security Engine",
    description="Pre-conversion file security analysis service for FilesMagic.",
    version="0.1.0",
)


# Registered before CORS so CORS stays the outer layer and the 413 still carries
# CORS headers (otherwise the browser would report a network error instead).
@app.middleware("http")
async def reject_oversized_uploads(request: Request, call_next):
    # Early rejection from the declared size, before the body is received. Clients
    # that omit Content-Length are still caught by the exact check in scan_file.
    length = request.headers.get("content-length", "")
    if request.url.path == "/scan" and length.isdigit() and int(length) > MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES:
        return JSONResponse({"detail": UPLOAD_TOO_LARGE}, status_code=413)
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(os.environ.get("SECURITY_ENGINE_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)),
    allow_methods=["GET", "POST"],
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
    }


def expected_scan_failure_reason(error: Exception) -> str | None:
    """Describe known malformed-input failures without hiding unexpected defects.

    PDF/Office scanners wrap low-level failures in their own exception types.
    A parser error or explicit scanner limit is an expected rejection. Other
    wrapped errors could be programming bugs and still need a full traceback.
    Never log attacker-supplied exception text from the document itself.
    """
    cause = error.__cause__
    if isinstance(error, PdfScanError):
        if cause is None:
            return "PDF structure is invalid or exceeds analysis limits"
        if isinstance(cause, PdfReadError):
            return "PDF is malformed or truncated; its structure could not be read"
    if isinstance(error, OfficeScanError):
        if cause is None:
            return "Office document structure is invalid or exceeds analysis limits"
        if isinstance(cause, (BadZipFile, XMLParseError, DefusedXmlException)):
            return "Office ZIP/XML structure is malformed or unreadable"
    return None


# Sync def so FastAPI runs it in a worker thread; scanners are blocking calls.
@app.post("/scan", response_model=ScanResult)
def scan_file(file: UploadFile = File(...)) -> ScanResult:
    filename = file.filename or ""
    # Read at most one byte past the limit, so an oversized upload never fully
    # enters memory. TODO: add authentication and rate limiting before real samples.
    data = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=UPLOAD_TOO_LARGE)

    findings: list[Finding] = []
    failed = not_applicable = 0
    for scanner in SCANNERS:
        try:
            result = scanner.scan(filename, data)
        except Exception as error:
            # Expected malformed documents are scan outcomes, not server crashes.
            # Keep tracebacks for surprises, including bugs wrapped by scanners.
            reason = expected_scan_failure_reason(error)
            if reason is not None:
                logger.warning(
                    "Scanner %s could not analyse %r: %s (%s).",
                    scanner.name, filename[:120], reason,
                    type(error.__cause__ or error).__name__,
                )
            else:
                logger.exception("Unexpected scanner failure in %s on %r", scanner.name, filename[:120])
            failed += 1
            continue
        if result is None:  # e.g. the Office scanner on a PDF
            not_applicable += 1
        else:
            findings.extend(result)

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

    return ScanResult(filename=filename, verdict=verdict, findings=findings, message=message)
