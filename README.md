# FilesMagic Security Engine

A pre-conversion security analysis service for FilesMagic, a file-conversion
application. Every uploaded file is meant to pass through this engine *before* it
reaches the FilesMagic conversion pipeline, so dangerous files can be rejected
early. Honors capstone project.

## Current status

**Phase 1: architecture and contracts. No security scanners are implemented yet.**

What exists:

- FastAPI service with `GET /health` and `POST /scan`
- Shared models (`app/models.py`): `Verdict`, `Severity`, `Finding`, `ScanResult`
- Scanner contract (`app/scanners/base.py`) that future scanners implement
- Deterministic decision engine (`app/decision/`) that combines findings into a verdict
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

- Health check: `curl http://127.0.0.1:8000/health`
- Scan a file: `curl -F "file=@example.pdf" http://127.0.0.1:8000/scan`
- Interactive docs: http://127.0.0.1:8000/docs

## Running tests

```bash
pytest
```

## Safety and isolation

Malicious files and security test samples (including EICAR-style test files) belong
**only** in the isolated Ubuntu VirtualBox testing environment. They must **never**
be committed to this repository, copied to a development machine, or opened outside
the isolated VM. `.gitignore` excludes the common sample and result directories
(`samples/`, `tests/samples/`, `quarantine/`, and others) as a safety net, but that
does not replace keeping samples out of this repository entirely.
