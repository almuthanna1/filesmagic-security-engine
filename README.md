# FilesMagic Security Engine

A pre-conversion security analysis service for FilesMagic, a file-conversion
application. Every uploaded file is meant to pass through this engine *before* it
reaches the FilesMagic conversion pipeline, so dangerous files can be rejected
early. Honors capstone project.

## Current status

**Phase 2B: deployment baseline (Render + Vercel). No security scanners are implemented yet.**

What exists:

- FastAPI service with `GET /health` and `POST /scan`
- Shared models (`app/models.py`): `Verdict`, `Severity`, `Finding`, `ScanResult`
- Scanner contract (`app/scanners/base.py`) that future scanners implement
- Deterministic decision engine (`app/decision/`) that combines findings into a verdict
- Security Lab web interface (`frontend/`) for uploading test files to `POST /scan`
- Deployment configuration: `Dockerfile` and `render.yaml` (API on Render), `frontend/` on Vercel
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

Developed on Python 3.14; the production image uses Python 3.11 (3.10+ is required).

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements-dev.txt   # runtime + test tooling
```

`requirements.txt` holds runtime dependencies only (that is what the Docker image
installs); `requirements-dev.txt` adds pytest and httpx.

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

## Deployment

Deployment is configured but **not yet performed**.

```
Isolated Ubuntu VM (browser)
        │ HTTPS
        ▼
Vercel ─ Security Lab (Next.js, frontend/)
        │ HTTPS, browser calls the API directly (CORS)
        ▼
Render ─ Security Engine API (FastAPI, Docker)
        │
        ▼
Future scanner layers: ClamAV, YARA-X, oletools, PDF analysis
```

### Backend on Render

- `Dockerfile`: `python:3.11-slim`, installs `requirements.txt`, runs uvicorn as a
  non-root user on `0.0.0.0:$PORT` (Render sets `PORT`, default 10000). No `--reload`.
- `.dockerignore`: allow-list, so only `app/` and `requirements.txt` enter the image.
- `render.yaml`: a Blueprint for one Docker web service with health check `/health`
  and auto-deploy off (deploy manually from the dashboard). It sets no instance type:
  choose one when creating the service (Render's default if none is chosen is the
  paid `0.5c-512mb`).

`GET /health` returns `{"status": "ok", ..., "scanners_registered": 0}`. It reports
that the API process is running, not that any scanner is installed.

### Frontend on Vercel

Import the repository in Vercel with **Root Directory = `frontend`**. Vercel
detects Next.js; no `vercel.json` is needed.

### Environment variables

| Variable | Where | Value |
|----------|-------|-------|
| `NEXT_PUBLIC_SECURITY_ENGINE_URL` | Vercel (Production) | The Render service URL, e.g. `https://<service>.onrender.com`. Inlined at build time, so **redeploy** the frontend after changing it. Public by design: never put secrets in `NEXT_PUBLIC_` variables. |
| `SECURITY_ENGINE_CORS_ORIGINS` | Render | The exact Vercel production origin, e.g. `https://<project>.vercel.app`: scheme + host, no path, no trailing slash. Comma-separate multiple origins. Never `*` (the API refuses to start). |

If `SECURITY_ENGINE_CORS_ORIGINS` is unset, the API allows only
`http://localhost:3000` and `http://127.0.0.1:3000`, so a deployed frontend is
blocked until the variable is set. Vercel preview deployments have different
origins; they are only allowed if listed explicitly.

### Deployment order

1. Deploy the backend to Render (New → Blueprint, select this repository).
2. Copy the Render HTTPS service URL.
3. In Vercel, set `NEXT_PUBLIC_SECURITY_ENGINE_URL` to that URL.
4. Deploy `frontend/` to Vercel.
5. Copy the final Vercel production origin.
6. In Render, set `SECURITY_ENGINE_CORS_ORIGINS` to that exact origin.
7. Redeploy/restart the Render service so the new value is loaded.
8. Verify frontend → backend communication (below).
9. Test the deployed Security Lab from the isolated Ubuntu VM.

### Verification

```bash
curl https://<service>.onrender.com/health
# {"status":"ok","service":"filesmagic-security-engine","scanners_registered":0}
```

Then upload a **benign** file (e.g. a small `.txt`) through the deployed Security Lab:

- the backend receives it (visible in Render logs),
- the verdict is `UNABLE_TO_SCAN`,
- findings are empty,
- the message states the file has NOT been security-scanned.

On the free instance type the service sleeps when idle; the first request after a pause can
take up to a minute, and the Security Lab may report the API as unreachable until it
wakes. Retry after `/health` responds.

**Only benign files may be uploaded to the deployed service until the
pre-malware-testing safeguards (upload size limits, access control, scanner
isolation) are in place.**
