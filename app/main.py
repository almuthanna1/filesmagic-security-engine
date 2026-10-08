import logging
import os

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.decision import decide
from app.models import Finding, ScanResult, Verdict
from app.scanners import SCANNERS

logger = logging.getLogger(__name__)

# Origins of the Security Lab frontend allowed to call the API from a browser.
DEFAULT_CORS_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(os.environ.get("SECURITY_ENGINE_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)),
    allow_methods=["GET", "POST"],
)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "filesmagic-security-engine",
    }


# Sync def so FastAPI runs it in a worker thread; scanners are blocking calls.
@app.post("/scan", response_model=ScanResult)
def scan_file(file: UploadFile = File(...)) -> ScanResult:
    filename = file.filename or ""
    # TODO: This reads the complete upload into memory. An explicit upload-size and
    # resource limit must be implemented before production use.
    data = file.file.read()

    findings: list[Finding] = []
    failed = 0
    for scanner in SCANNERS:
        try:
            findings.extend(scanner.scan(filename, data))
        except Exception:
            logger.exception("Scanner %s failed on %r", scanner.name, filename)
            failed += 1

    verdict = decide(findings, scanners_run=len(SCANNERS), scanners_failed=failed)

    if not SCANNERS:
        message = "No security scanners are configured yet. This file has NOT been security-scanned."
    elif failed and verdict == Verdict.UNABLE_TO_SCAN:
        message = f"{failed} of {len(SCANNERS)} scanners failed, so the file could not be fully analysed."
    else:
        message = f"Analysed by {len(SCANNERS) - failed} of {len(SCANNERS)} scanners."

    return ScanResult(filename=filename, verdict=verdict, findings=findings, message=message)
