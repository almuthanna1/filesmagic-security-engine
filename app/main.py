from fastapi import FastAPI, File, UploadFile

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


@app.post("/scan")
async def scan_file(file: UploadFile = File(...)):
    return {
        "filename": file.filename,
        "verdict": "UNSCANNED",
        "findings": [],
        "message": "Security scanners have not been integrated yet.",
    }