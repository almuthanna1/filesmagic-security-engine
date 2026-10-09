# FilesMagic Security Engine

A pre-conversion security analysis service for FilesMagic, a file-conversion
application. Every uploaded file is meant to pass through this engine *before* it
reaches the FilesMagic conversion pipeline, so dangerous files can be rejected
early. Honors capstone project.

## Current status

**Phase 3: YARA-X is the first implemented scanner. Office and PDF analysers are next.**
The deployed backend is still the Phase 2B baseline (no scanners) until redeployed.

What exists:

- FastAPI service with `GET /health` and `POST /scan`
- Shared models (`app/models.py`): `Verdict`, `Severity`, `Finding`, `ScanResult`
- Scanner contract (`app/scanners/base.py`) that future scanners implement
- Deterministic decision engine (`app/decision/`) that combines findings into a verdict
- Security Lab web interface (`frontend/`) for uploading test files to `POST /scan`
- Deployment configuration: `Dockerfile` and `render.yaml` (API on Render), `frontend/` on Vercel
- YARA-X scanner (`app/scanners/yarax.py`) with a small curated rule set (`app/rules/`)
- 10 MB upload limit on `POST /scan`
- pytest suite

## Security architecture

FilesMagic uses a **lightweight, multilayer, file-aware** engine instead of a
full antivirus. Each layer reports explainable findings; the decision engine
combines them into one verdict.

| Layer | Tool | Status |
|-------|------|--------|
| 1 | YARA-X: curated rules for risky structures in supported file types | **Implemented** |
| 2 | Office analysis: oletools, OOXML structure (macros, auto-exec, embedded objects, external relationships, ActiveX, DDE, encryption) | Planned |
| 3 | PDF analysis: pypdf + structural checks (JavaScript, open/launch actions, embedded files, URIs, forms, encryption) | Planned |
| 4 | General structural protections (type/signature validation, archive safety, size/resource limits) | Partly (upload limit) |

**Why not ClamAV:** ClamAV needs about 1.2 GiB of RAM just to load its signatures
(its documentation recommends 3-4 GiB). That does not fit the production budget
(a Render instance of at most ~$25/month), so ClamAV is not part of the production
engine. It may be used separately in the isolated test VM as a reference baseline.

**What this is not:** YARA-X with a small rule set is **not** an antivirus and does
not provide complete malware coverage. `SAFE` means "every configured scanner ran and
found no known indicator", not "proven harmless". Detection effectiveness (precision,
recall, F1, false positives) and cost (latency, CPU, memory) will be measured
empirically against independently labelled benign and malicious datasets.

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

### YARA-X scanner

- Rules: every `app/rules/*.yar` file, compiled once at startup with the `yara-x`
  Python package (Rust engine, prebuilt wheels, no system packages needed).
- Each rule **must** declare `description`, `category` (kebab-case) and `severity`
  (`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`); the compiler rejects rules without them.
  A match becomes a `Finding` with `scanner = "yara-x"` and `rule_id` = rule name.
- Bytes are scanned in memory; files are never executed. Each scan has a 10 s
  timeout and tracks at most 1000 matches per pattern (bounds memory).
- If rules cannot be loaded (package missing, syntax error, missing metadata), the
  scanner stays registered but **not ready**, and scans are `UNABLE_TO_SCAN`.

Initial rules (`app/rules/filesmagic.yar`):

| Rule | Severity | Detects |
|------|----------|---------|
| `PDF_Launch_Action` | HIGH | PDF `/Launch` action (can start programs) |
| `PDF_JavaScript_With_Automatic_Action` | MEDIUM | PDF JavaScript plus `/OpenAction` or `/AA` |
| `PDF_Embedded_File` | LOW | PDF file attachment |
| `OLE_Office_VBA_Macros` | MEDIUM | Legacy Office file with a VBA project |
| `OOXML_VBA_Macros` | MEDIUM | `.docm`/`.xlsm`-style file containing `vbaProject.bin` |
| `RTF_Auto_Updating_Embedded_Object` | HIGH | RTF `\objupdate` embedded object (exploit trigger technique) |
| `RTF_DDE_Auto_Field` | MEDIUM | RTF `DDEAUTO` field |
| `SVG_Script_Content` | MEDIUM | SVG with `<script>`, event handlers or `javascript:` |
| `Native_Executable` | MEDIUM | Windows PE or Linux ELF executable |

Rules match raw bytes only: content in compressed PDF streams or compressed OOXML
parts, and obfuscated PDF names (`/J#61vaScript`), are invisible to them. The
planned PDF and Office analysers parse those structures. To add a rule, put it in
`app/rules/` with the three metadata fields and add a trigger and a benign case to
`tests/test_yarax.py`.

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

pip install -r requirements-dev.txt   # runtime (incl. yara-x) + test tooling
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
upload controlled test files. Scans show whatever the engine returns, currently the
YARA-X verdict.

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

Malicious files and security test samples belong
**only** in the isolated Ubuntu VirtualBox testing environment. They must **never**
be committed to this repository, copied to a development machine, or opened outside
the isolated VM. `.gitignore` excludes the common sample and result directories
(`samples/`, `tests/samples/`, `quarantine/`, and others) as a safety net, but that
does not replace keeping samples out of this repository entirely. The tests use only
tiny synthetic byte strings that contain a rule's structural markers (e.g. `%PDF-`
and `/Launch`); they are not malware.

`POST /scan` rejects files over **10 MB** with HTTP 413: early from the declared
`Content-Length`, and exactly while reading the file (at most 10 MB + 1 byte is read).

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
YARA-X (in-process); later Office and PDF analysers
```

### Backend on Render

- `Dockerfile`: `python:3.11-slim`, installs `requirements.txt`, runs uvicorn as a
  non-root user on `0.0.0.0:$PORT` (Render sets `PORT`, default 10000). No `--reload`.
- `.dockerignore`: allow-list, so only `app/` and `requirements.txt` enter the image.
- `render.yaml`: a Blueprint for one Docker web service with health check `/health`
  and auto-deploy off (deploy manually from the dashboard). It sets no instance type:
  choose one when creating the service (Render's default if none is chosen is the
  paid `0.5c-512mb`).

`GET /health` returns `{"status": "ok", ..., "scanners_registered": 1, "scanners_ready": 1}`.
`status` means the API process is up; `scanners_ready` counts scanners that loaded
(e.g. YARA-X rules compiled). If it is lower than `scanners_registered`, scans are
`UNABLE_TO_SCAN`.

Measured locally (Windows, Python 3.14, not yet on Render): the API process with
YARA-X loaded uses about 55 MiB; scanning a 10 MB file adds about 10 MiB and takes
milliseconds. This suggests the free 512 MB instance is enough, but it must be
benchmarked on Render.

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
# {"status":"ok","service":"filesmagic-security-engine","scanners_registered":1,"scanners_ready":1}
```

Then upload a **benign** file (e.g. a small `.txt`) through the deployed Security Lab:

- the backend receives it (visible in Render logs),
- the verdict is `SAFE` with no findings, and the message says this is not a guarantee,
- a file over 10 MB is rejected with "File is too large".

On the free instance type the service sleeps when idle; the first request after a pause can
take up to a minute, and the Security Lab may report the API as unreachable until it
wakes. Retry after `/health` responds.

**Only benign files may be uploaded to the deployed service until the
pre-malware-testing safeguards (access control, rate limiting, scanner isolation)
are in place.**
