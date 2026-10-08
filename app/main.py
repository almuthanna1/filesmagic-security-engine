import logging

from fastapi import FastAPI, File, UploadFile

from app.decision import decide
from app.models import Finding, ScanResult, Verdict
from app.scanners import SCANNERS

logger = logging.getLogger(__name__)

app = FastAPI(
    title="FilesMagic Security Engine",
    description="Pre-conversion file security analysis service for FilesMagic.",
    version="0.1.0",
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
