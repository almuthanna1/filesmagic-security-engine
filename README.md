# FilesMagic Security Engine

A pre-conversion security analysis service for FilesMagic, a file-conversion
application. Every uploaded file is meant to pass through this engine *before* it
reaches the FilesMagic conversion pipeline, so dangerous files can be rejected
early. Honors capstone project.

## Current status

**Phase 2A: local Security Lab interface. No security scanners are implemented yet.**

What exists:

- FastAPI service with `GET /health` and `POST /scan`
- Shared models (`app/models.py`): `Verdict`, `Severity`, `Finding`, `ScanResult`
- Scanner contract (`app/scanners/base.py`) that future scanners implement
- Deterministic decision engine (`app/decision/`) that combines findings into a verdict
- Security Lab web interface (`frontend/`) for uploading test files to `POST /scan`
- pytest suite

Because no scanners are registered, `POST /scan` currently returns
`UNABLE_TO_SCAN` for every file. It **never** reports `SAFE` without real analysis.

## Planned scanner architecture

| Layer | Tool | Purpose |
|-------|------|---------|
| 1 | ClamAV | Known and generic malware signatures |
| 2 | YARA-X | Rule-based detection (rules will live in `rules/`) |
| 3 | oletools / olevba | Microsoft Office VBA and macro analysis |
| 4 | pypdf + custom checks | Dangerous PDF features (JavaScript, auto-actions, embedded files) |

Each scanner implements the `Scanner` protocol:

```python
class Scanner(Protocol):
    name: str
    def scan(self, filename: str, data: bytes) -> list[Finding]: ...
```

It returns a list of findings (empty means nothing was found) or raises an exception
if it could not analyse the file. Scanners are registered in `SCANNERS` in
`app/scanners/__init__.py`. `POST /scan` runs every registered scanner and passes
the combined findings to `decide()`.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `SAFE` | Every configured scanner analysed the file and found nothing above `INFO` |
| `SUSPICIOUS` | At least one `LOW` or `MEDIUM` finding, and no `HIGH`/`CRITICAL` finding |
| `MALICIOUS` | At least one `HIGH` or `CRITICAL` finding |
| `UNABLE_TO_SCAN` | No scanners are configured, or a scanner failed, and no finding of `LOW` or higher was produced |

Evidence takes priority over failures: if one scanner crashes and another reports a
`HIGH` finding, the verdict is still `MALICIOUS`.

## Development setup

Requires Python 3.14 (the version this was developed on; 3.10+ should work).

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

## Running the API

```bash
uvicorn app.main:app --reload
```

- Health check: `curl http://localhost:8000/health`
- Scan a file: `curl -F "file=@example.pdf" http://localhost:8000/scan`
- Interactive docs: http://localhost:8000/docs

### CORS

Browsers may only call the API from origins on an explicit allow-list, set with the
`SECURITY_ENGINE_CORS_ORIGINS` environment variable (comma-separated). It defaults
to the local Security Lab origins, `http://localhost:3000,http://127.0.0.1:3000`.
A wildcard (`*`) is rejected at startup.

```bash
# Linux/macOS
SECURITY_ENGINE_CORS_ORIGINS="https://lab.example.com" uvicorn app.main:app
# Windows PowerShell
$env:SECURITY_ENGINE_CORS_ORIGINS="https://lab.example.com"; uvicorn app.main:app
```

## Security Lab (frontend)

`frontend/` contains the FilesMagic Security Lab, an internal testing interface
(not the public FilesMagic site). Upload a file, scan it, and inspect the verdict and
findings exactly as the engine returned them. It is a Next.js + TypeScript app.

It will eventually be deployed so the isolated Ubuntu VM can open it in a browser and
upload controlled test files. Deployed scanner infrastructure (a container host for
ClamAV and the other scanners) comes in a later phase. Until then, every scan shows
`UNABLE_TO_SCAN`, because no scanner is integrated yet.

**Prerequisites:** Node.js 20.9+ (developed on Node 24) and npm.

**Install and configure:**

```bash
cd frontend
npm install
cp .env.example .env.local   # Windows PowerShell: Copy-Item .env.example .env.local
```

| Variable | Purpose | Local value |
|----------|---------|-------------|
| `NEXT_PUBLIC_SECURITY_ENGINE_URL` | Base URL of the Security Engine API. Inlined at build time, so rebuild after changing it. | `http://localhost:8000` |

Never commit `.env.local` or any real `.env` file.

**Run both services locally** (two terminals):

```bash
# Terminal 1, repo root, venv active
uvicorn app.main:app --reload --port 8000

# Terminal 2
cd frontend
npm run dev
```

| Service | URL |
|---------|-----|
| Security Lab | http://localhost:3000 |
| Engine API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

Other frontend commands: `npm run lint`, `npx tsc --noEmit`, `npm run build`.

## Running tests

```bash
pytest          # backend, from the repo root
```

## Safety and isolation

Malicious files and security test samples (including EICAR-style test files) belong
**only** in the isolated Ubuntu VirtualBox testing environment. They must **never**
be committed to this repository, copied to a development machine, or opened outside
the isolated VM. `.gitignore` excludes the common sample and result directories
(`samples/`, `tests/samples/`, `quarantine/`, and others) as a safety net, but that
does not replace keeping samples out of this repository entirely.
