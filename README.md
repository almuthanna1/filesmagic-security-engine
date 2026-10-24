# FilesMagic Security Engine

A pre-conversion security analysis service for FilesMagic, a file-conversion
application. Every uploaded file is meant to pass through this engine *before* it
reaches the FilesMagic conversion pipeline, so dangerous files can be rejected
early. Honors capstone project.

## Current status

**Phase 3C: YARA-X, Office and PDF analysis are implemented. Next: review the stack and benchmark on Render.**
Not production-ready: detection quality has not been evaluated yet.
The deployed backend is still the Phase 2B baseline (no scanners) until redeployed.

What exists:

- FastAPI service with `GET /health` and `POST /scan`
- Shared models (`app/models.py`): `Verdict`, `Severity`, `Finding`, `ScanResult`
- Scanner contract (`app/scanners/base.py`) that future scanners implement
- Deterministic decision engine (`app/decision/`) that combines findings into a verdict
- Security Lab web interface (`frontend/`) for uploading test files to `POST /scan`
- Deployment configuration: `Dockerfile` and `render.yaml` (API on Render), `frontend/` on Vercel
- YARA-X scanner (`app/scanners/yarax.py`) with a small curated rule set (`app/rules/`)
- Office scanner (`app/scanners/office.py`): structural analysis of OLE and OOXML documents
- PDF scanner (`app/scanners/pdf.py`): structural analysis of PDF documents
- 10 MB upload limit on `POST /scan`
- Scan authorization: short-lived, single-use, file-bound Ed25519 tokens issued by the Lab after admin login (`app/auth.py`)
- Per-scan isolated worker process with resource limits (`app/worker.py`)
- Malware Evaluation workflow in the Security Lab (`/evaluation`) with CSV/JSON export

Readiness for real malicious samples: **BLOCKED**, see
[docs/malware-research-readiness.md](docs/malware-research-readiness.md).
- pytest suite

## Security architecture

FilesMagic uses a **lightweight, multilayer, file-aware** engine instead of a
full antivirus. Each layer reports explainable findings; the decision engine
combines them into one verdict.

| Layer | Tool | Status |
|-------|------|--------|
| 1 | YARA-X: curated rules for risky byte patterns in supported file types | **Implemented** |
| 2 | Office analysis: oletools + OOXML ZIP/XML structure (macros, auto-exec, embedded objects, external relationships, ActiveX, DDE, encryption, package abuse) | **Implemented** |
| 3 | PDF analysis: pypdf + structural walk (JavaScript, automatic actions, launch actions, embedded files, URIs, forms, encryption) | **Implemented** |
| 4 | General structural protections (type/signature validation, archive safety, size/resource limits) | Partly (upload limit) |

**Why not ClamAV:** ClamAV needs about 1.2 GiB of RAM just to load its signatures
(its documentation recommends 3-4 GiB). That does not fit the production budget
(a Render instance of at most ~$25/month), so ClamAV is not part of the production
engine. It may be used separately in the isolated test VM as a reference baseline.

The layers complement each other:

- **YARA-X**: rule/pattern matching on raw bytes of any file, including formats no
  structural analyser understands (RTF, SVG, executables).
- **Office scanner**: semantic/structural analysis of Office documents (compressed
  XML parts, relationship targets, macro behaviour).
- **PDF scanner**: semantic/structural analysis of PDFs (objects inside compressed
  object streams, what triggers an action, attachment types).
- **Decision engine**: combines all explainable findings into one verdict.

**What this is not:** these layers are **not** an antivirus and do not provide
complete malware coverage. `SAFE` means "every configured scanner ran and
found no known indicator", not "proven harmless". Detection effectiveness (precision,
recall, F1, false positives) and cost (latency, CPU, memory) will be measured
empirically against independently labelled benign and malicious datasets.

Each scanner implements the `Scanner` protocol:

```python
class Scanner(Protocol):
    name: str
    def scan(self, filename: str, data: bytes) -> list[Finding] | None: ...
```

It returns a list of findings (empty means nothing was found), returns `None` if the
file is not a format it handles (e.g. the Office scanner given a PDF), or raises an
exception if it could not analyse the file. Not-applicable scanners count neither
as analysis nor as failure; a file that **no** scanner handles is `UNABLE_TO_SCAN`. Scanners are registered in `SCANNERS` in
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
parts, and obfuscated PDF names (`/J#61vaScript`), are invisible to them. The Office
and PDF scanners parse those structures. The macro and PDF rules overlap with the
structural scanners on purpose: they are an independent second signal and still fire
when a structural parser does not recognise or cannot parse a file. To add a rule, put it in
`app/rules/` with the three metadata fields and add a trigger and a benign case to
`tests/test_yarax.py`.

### Office scanner

Identifies the format from content, never the file extension:

- **OLE2 compound file** with Office streams (`.doc`, `.xls`, `.ppt`, and encrypted
  OOXML, which is stored as OLE). Other OLE files (MSI, Outlook `.msg`) are not applicable.
- **OOXML package**: a ZIP containing `[Content_Types].xml` (`.docx/.docm`,
  `.xlsx/.xlsm`, `.pptx/.pptm`, templates). Other ZIPs are not applicable.

| Check | How | Severity |
|-------|-----|----------|
| VBA/XLM macro project present | olevba | LOW |
| VBA project storage that cannot be parsed | olevba | LOW |
| Macro auto-execution entry point (`AutoOpen`, `Document_Open`, …) | olevba | MEDIUM |
| Macro can run commands, download files, inject code; VBA stomping | olevba | MEDIUM |
| Other suspicious macro keywords / encoded strings | olevba | LOW |
| Auto-execution **and** command execution/download | olevba | HIGH |
| Excel 4.0 (XLM) macro sheets | OOXML parts | MEDIUM |
| External relationship loaded on open (`attachedTemplate`, `oleObject`, `frame`, `subDocument`) | `.rels` XML | MEDIUM |
| External target with a handler scheme (`mhtml:`, `ms-*:`, `search-ms:`, trailing `!`) | `.rels` XML | HIGH |
| External target on a network/file path (credential leak) | `.rels` XML | MEDIUM |
| Other external resources (e.g. linked images); ordinary hyperlinks ignored | `.rels` XML | INFO |
| Embedded OLE object | olefile | LOW |
| OLE Package object / with executable or script file name | oleobj | MEDIUM / HIGH |
| Equation Editor 3.0 object (CVE-2017-11882) | olefile CLSID | HIGH |
| ActiveX controls | OOXML parts | MEDIUM |
| Word `DDE` / `DDEAUTO` field (also split across runs) | field XML | MEDIUM / HIGH |
| Excel DDE link / to `cmd`, `powershell`, … | external-link XML | MEDIUM / HIGH |
| Password-protected / encrypted document | msoffcrypto-tool, OLE streams | MEDIUM |
| ZIP path traversal / absolute member names | ZIP headers | HIGH |
| Decompression bomb (>256 MB declared) or >5000 entries | ZIP headers | HIGH |
| Duplicate or ZIP-encrypted members | ZIP headers | MEDIUM |

A macro, link or embedded object alone is not treated as malicious; only strong
combinations or known exploit techniques are `HIGH`.

Safety: everything is parsed in memory (no temp files, no extraction to disk);
macros and objects are never executed; XML is parsed with defusedxml (DTDs and
entities rejected) and streamed; ZIP limits are checked from the headers before any
member is decompressed, and no single part over 32 MB is read. Any parser error makes
the Office result a failure (`UNABLE_TO_SCAN` unless other evidence exists).

Limitations: DDE in legacy `.doc`/`.xls` binary formats, QUOTE-obfuscated or nested
DDE fields, ActiveX in legacy OLE files, macros inside embedded documents (embedded
packages are not scanned recursively) and RTF documents (YARA-X only) are not
covered. The macro analysis relies on olevba's keyword heuristics.

### PDF scanner

A file is a PDF if `%PDF-` appears in its first 1024 bytes (where readers accept the
header), regardless of extension; anything else is not applicable. pypdf
(`strict=False`, as real-world PDFs are often slightly broken) parses it, and the
scanner walks the object graph from the document catalog, tracking whether each
action is reached through an **automatic trigger**: `/OpenAction`, document-level
JavaScript, or `/AA` page-open and document events. Form-field keystroke/format
scripts count as user-triggered.

| Check | Severity | Rationale |
|-------|----------|-----------|
| JavaScript present | MEDIUM | Often legitimate (forms), but active content |
| JavaScript run automatically on open | MEDIUM | Stronger signal, but Acrobat forms do this too |
| JavaScript using historic exploit APIs (`util.printf`, `Collab.getIcon`, …) or `exportDataObject` with `nLaunch` | HIGH | Known exploit / attachment-launch technique |
| Automatic JavaScript **and** an attachment or launch action | HIGH | Classic drop-and-open combination |
| `/Launch` action | HIGH | Starts programs or opens files |
| Embedded file | LOW | Attachments can be legitimate |
| Embedded executable/script/macro document (by name or MIME type) | HIGH | Payload carrier |
| Link with handler scheme (`javascript:`, `data:`, `ms-*:`, `search-ms:`, …) | HIGH | Hands the target to another program |
| Link to a network/file path | MEDIUM | Can leak credentials |
| Link with another uncommon scheme | INFO | Explained, no verdict impact |
| Ordinary `http(s)`/`mailto` links, `GoTo` open actions | not reported | Normal |
| AcroForm | INFO | Normal interactive form |
| XFA form | LOW | Can carry scripts not parsed here |
| Password-protected (needs a user password) | MEDIUM | Contents cannot be inspected |
| Encrypted with empty user password (permissions only) | INFO | Decrypted and fully inspected |
| Structure repaired by the parser | INFO | Evidence of malformation |

Safety: parsed in memory; JavaScript is only searched as text (at most 1 MB per
script) and never executed; URIs are only classified, never opened; attachments are
only inspected by name and MIME type, never extracted. pypdf runs with decompression
capped at 20 MB per stream and its external `jbig2dec` decoder disabled. The walk is
iterative, visits each object once per trigger context (so reference cycles end),
skips bulky branches that cannot hold actions (fonts, resources, page content,
appearance streams), and fails closed beyond 64 levels of nesting inside one object
or 200,000 visited objects. Any parser error makes the PDF result a failure.

Limitations: JavaScript is not deobfuscated or emulated, so detection of malicious
scripts beyond the listed APIs relies on context (automatic triggers, attachments);
XFA content, rich media/Flash, and `SubmitForm`/`ImportData`/`GoToR`/`GoToE` actions
are not analysed; attachments (e.g. an embedded Office file) are not scanned
recursively; a password-protected PDF can only be reported as uninspectable. Many
legitimate Acrobat forms use JavaScript and will be `SUSPICIOUS`.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `SAFE` | Every configured scanner analysed the file and found nothing above `INFO` |
| `SUSPICIOUS` | At least one `LOW` or `MEDIUM` finding, and no `HIGH`/`CRITICAL` finding |
| `MALICIOUS` | At least one `HIGH` or `CRITICAL` finding |
| `UNABLE_TO_SCAN` | No scanner handles the file, or a scanner failed, and no finding of `LOW` or higher was produced |

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
- Scan a file: the request body is the raw file, with a scan token (see "Access control"):
  `curl --data-binary @example.pdf -H "Authorization: Bearer <token>" -H "X-Filename: example.pdf" http://localhost:8000/scan`
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

### Access control

`POST /scan` requires `Authorization: Bearer <token>`. Tokens are minted by the Security
Lab's server-side route `/api/scan-token`, only for a logged-in administrator, and are:

- **Ed25519-signed**: the Lab (Vercel) holds the private key; the engine (Render) holds only
  the public key, so nothing on the scanning host can mint tokens;
- **short-lived** (120 s, at most 300 s accepted) and **single-use** (`jti` replay check);
- **bound to one file**: its SHA-256 and size, checked after upload (HTTP 403 on mismatch).

The browser hashes the file, gets a token, and uploads the file directly to Render; file
contents never pass through Vercel. The token is checked before any body byte is read, and
20 failed attempts per minute from one address make further requests from it HTTP 429. If
`SECURITY_ENGINE_TOKEN_PUBLIC_KEY` is unset, every scan is refused (`/health` reports
`auth_configured: false`).

Generate the keys and the admin password hash (Node 20+):

```bash
node -e "const k=require('crypto').generateKeyPairSync('ed25519');console.log('LAB_SCAN_TOKEN_PRIVATE_KEY='+k.privateKey.export({format:'der',type:'pkcs8'}).toString('base64'));console.log('SECURITY_ENGINE_TOKEN_PUBLIC_KEY='+k.publicKey.export({format:'der',type:'spki'}).toString('base64'))"
node -e "const c=require('crypto');console.log('LAB_SESSION_SECRET='+c.randomBytes(32).toString('base64url'))"
node -e "const c=require('crypto'),s=c.randomBytes(16);console.log('LAB_ADMIN_PASSWORD_HASH=scrypt$'+s.toString('base64')+'$'+c.scryptSync(process.argv[1],s,32).toString('base64'))" "<your long password>"
```

### Scan isolation

Each scan runs every scanner in a fresh `python -m app.worker` child process with an empty
environment; the API never parses a document itself (it only hashes it and reads magic
bytes). The parent enforces a wall-clock timeout (30 s), caps the worker's output at 1 MB,
kills the child's whole process group afterwards, and turns any crash, timeout or invalid
report into `UNABLE_TO_SCAN`. Before reading the document the child applies, where the
platform allows, two kinds of control:

- **Kernel-enforced (Linux):** rlimits (CPU 20 s, writable memory, no file writes, 32 open
  files, no new processes/threads, no core dumps) and, if unprivileged namespaces are
  allowed, a new user + network namespace with no network interfaces.
- **In-process guard only:** a Python audit hook that refuses sockets, DNS, process
  creation, `ctypes` library loading and opening files for writing. It catches Python code
  paths in the parsers; it is **not** an operating-system security boundary, and native
  code (or a memory-corruption exploit) is not subject to it.

Each result reports which controls were actually applied (`isolation`). With
`SECURITY_ENGINE_REQUIRE_ISOLATION=1` a worker refuses to analyse anything unless all of
them are in place. The kernel controls are exercised by `tests/test_worker_linux.py`
(Linux only; CI in `.github/workflows/security-engine-tests.yml`, where they may not skip).

**Logging.** Log lines carry only controlled values: a per-request `request_id` (also returned
in the scan result), scanner name, failure kind (`malformed_input`, `invalid_structure`,
`unexpected`, `worker`), exception type, a SHA-256 prefix and the verdict. Expected failures on
malformed files are concise warnings; `unexpected` failures (possible scanner bugs) are errors
with a code-location trace (`file:line:function` frames). Filenames, file contents and
exception messages are never logged, because they can be attacker-controlled.

This is defence in depth, **not a sandbox**: the worker runs as the same user in the same
container as the API. See [docs/malware-research-readiness.md](docs/malware-research-readiness.md).

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
| `LAB_ADMIN_PASSWORD_HASH`, `LAB_SESSION_SECRET`, `LAB_SCAN_TOKEN_PRIVATE_KEY` | Server-only login and token signing (see "Access control"). | generated locally |

Pages: `/` (simple scanner) and `/evaluation` (Malware Evaluation: record each sample's
source dataset and independently verified classification next to the observed verdict,
findings, scanner status, versions, duration and isolation; export as CSV or JSON). Records
hold results only, never file contents, and stay in the browser's localStorage.

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
`Content-Length`, and exactly while streaming the body into memory (chunked uploads
included; nothing is spooled to disk). An upload that takes over 60 s gets HTTP 408, and
only `SECURITY_ENGINE_MAX_CONCURRENT_SCANS` scans run at once (HTTP 429 beyond).

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
isolated worker process per scan: YARA-X + Office + PDF analysis
```

### Backend on Render

- `Dockerfile`: `python:3.11-slim`, installs `requirements.txt`, runs uvicorn as a
  non-root user on `0.0.0.0:$PORT` (Render sets `PORT`, default 10000). No `--reload`.
- `.dockerignore`: allow-list, so only `app/` and `requirements.txt` enter the image.
- `render.yaml`: a Blueprint for one Docker web service with health check `/health`
  and auto-deploy off (deploy manually from the dashboard). It sets no instance type:
  choose one when creating the service (Render's default if none is chosen is the
  paid `0.5c-512mb`).

`GET /health` returns `{"status": "ok", ..., "scanners_registered": 3, "scanners_ready": 3}`.
`status` means the API process is up; `scanners_ready` counts scanners that loaded
(e.g. YARA-X rules compiled). If it is lower than `scanners_registered`, scans are
`UNABLE_TO_SCAN`.

Measured locally (Windows, Python 3.14, not on Render): the API process with all
three scanners loaded uses about 71 MiB. Typical Office and PDF scans take
milliseconds; a document with 28 MB of uncompressed XML took about 0.25 s, a PDF with
3000 links about 0.3 s, and a PDF made of tens of thousands of tiny objects about
0.36 s per 10,000 objects (so a pathological 10 MB PDF hits the object limit and
fails closed after a few seconds). This suggests the free 512 MB instance is enough,
but it must be benchmarked on Render.

### Frontend on Vercel

Import the repository in Vercel with **Root Directory = `frontend`**. Vercel
detects Next.js; no `vercel.json` is needed.

### Environment variables

| Variable | Where | Value |
|----------|-------|-------|
| `LAB_ADMIN_PASSWORD_HASH`, `LAB_SESSION_SECRET`, `LAB_SCAN_TOKEN_PRIVATE_KEY` | Vercel (Production, sensitive) | See "Access control". Never `NEXT_PUBLIC_`. |
| `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` | Render | Public half of the token key pair. Required: without it every scan is refused. |
| `SECURITY_ENGINE_MAX_CONCURRENT_SCANS` | Render (optional) | Default `1` (sized for 512 MB). |
| `SECURITY_ENGINE_WORKER_MEMORY_MB` | Render (optional) | Writable memory per worker, default `320`. |
| `SECURITY_ENGINE_WORKER_TIMEOUT_SECONDS` | Render (optional) | Default `30`. |
| `SECURITY_ENGINE_REQUIRE_ISOLATION` | Render (optional) | `1` = refuse to scan without every isolation control. Required for real malware. |
| `NEXT_PUBLIC_SECURITY_ENGINE_URL` | Vercel (Production) | The Render service URL, e.g. `https://<service>.onrender.com`. Inlined at build time, so **redeploy** the frontend after changing it. Public by design: never put secrets in `NEXT_PUBLIC_` variables. |
| `SECURITY_ENGINE_CORS_ORIGINS` | Render | The exact Vercel production origin, e.g. `https://<project>.vercel.app`: scheme + host, no path, no trailing slash. Comma-separate multiple origins. Never `*` (the API refuses to start). |

If `SECURITY_ENGINE_CORS_ORIGINS` is unset, the API allows only
`http://localhost:3000` and `http://127.0.0.1:3000`, so a deployed frontend is
blocked until the variable is set. Vercel preview deployments have different
origins; they are only allowed if listed explicitly.

### Deployment order

**Upgrading an existing deployment** from the multipart/no-auth version: the old and new
Lab and engine are incompatible in both directions, so they must be switched (and rolled
back) together. Follow the coordinated plan in
[docs/malware-research-readiness.md](docs/malware-research-readiness.md), section 9.

First deployment from scratch (also generate and set the access-control variables above):

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
# {"status":"ok","service":"filesmagic-security-engine","scanners_registered":3,"scanners_ready":3}
```

Then upload a **benign** file (e.g. a small `.txt`) through the deployed Security Lab:

- the backend receives it (visible in Render logs),
- the verdict is `SAFE` with no findings, and the message says this is not a guarantee,
- a file over 10 MB is rejected with "File is too large".

On the free instance type the service sleeps when idle; the first request after a pause can
take up to a minute, and the Security Lab may report the API as unreachable until it
wakes. Retry after `/health` responds.

**Only benign files may be uploaded to the deployed service.** Access control, rate
limiting and per-scan worker isolation are implemented, but real-malware testing remains
**BLOCKED** on hosting prerequisites; see
[docs/malware-research-readiness.md](docs/malware-research-readiness.md).
