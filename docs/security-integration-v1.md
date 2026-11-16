# FilesMagic Security Integration Contract, v1

**Status:** authoritative contract for the FilesMagic Conversion Engine ↔ Security Engine integration.
Implemented on branch `feature/production-scan-integration-v1`. **Not deployed.** Production
(`srv-db3r5cc9v7es73e57frg`, live `e6fdbd4`) is unchanged; see [Deployment prerequisites](#11-deployment-prerequisites).

**What SAFE means:** no known threats were detected by the completed required checks. It is
not proof that a file is harmless, and no FilesMagic surface may describe it as such.

---

## 1. Scope and base

FilesMagic scans PDF and Office documents before conversion. The Conversion Engine (server-side)
sends the stored upload's exact bytes to the Security Engine, verifies the signed **scan
receipt** it gets back, and converts only when the receipt allows it.

| Item | Value |
|---|---|
| Scanner implementation | Custom **Unified Engine** (`engine=unified`): the reference scanners (YARA-X, Office, PDF, custom) + engine signatures, PDF action chains, PDF page-content integrity, VBA call chains, OOXML links, Word fields: 10 scanners |
| Source base | `feature/custom-unified-engine-nov18` @ `d4bb56f` (staging, live `840a300`: CI-green PR #21 PDF coverage fail-closed, hosted regression evidence) **+** SE#3 `90718ff` (pypdf 6.19.0 → 7.0.1 for its published advisories; 0 of 504 accuracy results changed) merged as `458d96f`, **+** this contract |
| Why not plain `main` | `main` (`10fc660`; production runs `e6fdbd4`) is the 3-scanner reference engine: no unified engine, no coverage gating, no isolation verification reporting, and no conversion contract |
| Why not plain staging | It pins pypdf 6.19.0 (advisories fixed in 7.0.1) and has no receipts, reason codes or override policy |
| Why not plain 90718ff | It predates PR #21: an LZW-damaged page stream scanned **SAFE** there (qpdf `bad-data.pdf`); staging fails closed |

The reference engine, the research evaluation tooling (`evaluation/`), the Security Lab and its
token flow are unchanged and still pass their tests.

## 2. Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | Liveness + readiness (§9). Never returns secrets |
| `POST` | `/scan?engine=unified` | Bearer scan token | Scan the raw request body |

### `POST /scan?engine=unified`

| Header | Required | Value |
|---|---|---|
| `Authorization` | yes | `Bearer <scan token>` (§4), signed by the **Conversion Engine** token key |
| `Content-Type` | recommended | `application/octet-stream` |
| `Content-Length` | recommended | Exact byte count. Over 25 MiB is refused before reading |
| `X-Filename` | no | Percent-encoded, informational only; never used for any decision |

**Body:** the raw document bytes, nothing else (no multipart). Maximum **26,214,400 bytes**.

`engine=unified` must be explicit: a conversion token used with any other engine is refused
(`403 ENGINE_NOT_APPROVED`) and its token is consumed.

The engine **computes its own SHA-256 and size** of the bytes it received and refuses the scan
if they differ from the token's (`403 TOKEN_FILE_MISMATCH`). Client-supplied hashes, filenames
and verdicts are never trusted.

## 3. Response (HTTP 200)

Every completed request returns HTTP 200 with a `ScanResult`, including operational failures
(worker crash, timeout, isolation failure), which are reported in the body as
`verdict: UNABLE_TO_SCAN` with operational reasons and **no receipt**. Fields the Lab already
used are unchanged; v1 adds the last six.

```json
{
  "request_id": "4fd82aa4480e43ac",
  "engine": "unified",
  "filename": "",
  "verdict": "SAFE",
  "findings": [],
  "message": "Analysed by 6 of 10 scanners (4 not applicable to this file type). No known indicators were found; this is not a guarantee that the file is harmless.",
  "sha256": "29d46813a42650b0caba64f4c5c1d5c40afef7d7e6399b97b30a475424dc3c37",
  "size_bytes": 33558,
  "detected_format": "pdf",
  "scanners": [{"name": "pdf", "status": "completed", "error": null, "error_kind": null, "error_type": null, "duration_ms": 4.1}],
  "complete": true,
  "coverage_complete": true,
  "coverage_issues": [],
  "duration_ms": 12.2,
  "versions": {"engine": "0.2.0", "commit": "<40 hex>", "ruleset_sha256": "…", "engine_ruleset_sha256": "…",
               "yara-x": "1.21.0", "oletools": "0.60.2", "olefile": "0.47", "pypdf": "7.0.1"},
  "isolation_required": true,
  "isolation": {"process": true, "network_namespace": true, "network_verified": true, "…": true},
  "isolation_missing": [],
  "isolation_verified": true,
  "reasons": [],
  "override_eligible": false,
  "authorization": "allow",
  "explanation": "No known threats were detected by the completed security checks. This is not a guarantee that the file is harmless.",
  "receipt": "eyJhdWQiOi….<signature>"
}
```

(`scanners` and `isolation` abbreviated; real answers list all 10 scanners and 13 isolation values.)

| Field | Meaning |
|---|---|
| `verdict` | `SAFE`, `SUSPICIOUS`, `MALICIOUS`, `UNABLE_TO_SCAN` (rules in `app/decision`: HIGH/CRITICAL → MALICIOUS; LOW/MEDIUM → SUSPICIOUS; any failure or coverage gap → UNABLE_TO_SCAN; else SAFE) |
| `findings[]` | `scanner`, `category`, `severity`, `description`, `rule_id`, `evidence[]`. Control characters and file-system paths are stripped and every item is bounded (≤ 500 chars, ≤ 50 items). Text can still quote document content: **render it as text, never as HTML** |
| `complete` | Scanner completion: every applicable scanner returned |
| `coverage_complete` / `coverage_issues[]` | Content coverage: every required region was analysed; otherwise stable codes |
| `isolation_verified` | Strict isolation was required **and** every required control was reported true |
| `reasons[]` | `{code, category: "document"\|"operational", override_eligible, explanation}`, de-duplicated (§6) |
| `authorization` | `allow`, `consent_required` or `deny`: the policy result (§7). **Advisory in the body; only the receipt counts** |
| `override_eligible` | `authorization == "consent_required"` |
| `explanation` | Plain-English sentence for the user |
| `receipt` | Signed receipt (§5), or `null`. **`null` means deny** |

### Error responses

Errors that stop a scan before it runs are `{"detail": "<human text>", "code": "<CODE>"}`:

| HTTP | `code` | When | Conversion Engine maps to |
|---|---|---|---|
| 400 | `ENGINE_UNKNOWN` | `engine` is not `reference`/`unified` | unavailable (bug) |
| 401 | `AUTH_NOT_CONFIGURED` | The engine has no token key | unavailable |
| 401 | `AUTH_MISSING` | No/malformed `Authorization` | unavailable (bug) |
| 401 | `AUTH_INVALID` | Signature does not verify with a trusted issuer key | unavailable |
| 401 | `AUTH_EXPIRED_OR_INVALID_CLAIMS` | Expired, wrong audience, lifetime > 300 s, bad claims | unavailable |
| 401 | `AUTH_REPLAYED` | Token `jti` already used | unavailable |
| 403 | `ENGINE_NOT_ENABLED` | Unified engine not enabled on this deployment | unavailable |
| 403 | `ENGINE_NOT_APPROVED` | Conversion token with a non-unified engine | unavailable (bug) |
| 403 | `TOKEN_FILE_MISMATCH` | Received bytes' SHA-256/size ≠ token | unavailable |
| 408 | `UPLOAD_TIMEOUT` | Body not received within 60 s | unavailable |
| 413 | `UPLOAD_TOO_LARGE` | Over 25 MiB (declared or streamed) | file too large |
| 429 | `RATE_LIMITED` | ≥ 20 unauthorized requests/min from this address (`Retry-After: 60`) | busy |
| 429 | `ENGINE_BUSY` | Concurrency limit reached (`Retry-After: 5`) | busy |
| 503 | (no body code) | uvicorn connection limit (32) | busy |

Any non-200, any unparseable body, and any transport error = **deny**. Never retry with the
same token; mint a new one.

## 4. Scan tokens (request authentication)

Unchanged format, shared by both issuers: `base64url(JSON claims) "." base64url(Ed25519 signature over those exact JSON bytes)`.

```json
{"aud": "filesmagic-security-engine/scan", "iat": 1794791456, "exp": 1794791576,
 "jti": "<32 hex>", "sha256": "<64 hex of the bytes to be sent>", "size": 33558}
```

Single use (`jti`), lifetime ≤ 300 s (the Conversion Engine uses 120 s), 30 s clock skew.

| Issuer | Private key lives in | Engine verifies with | Gets receipts |
|---|---|---|---|
| `lab`: Security Lab (Vercel server route) | `LAB_SCAN_TOKEN_PRIVATE_KEY` (Vercel) | `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` | **never** |
| `conversion`: FilesMagic Conversion Engine | `SECURITY_ENGINE_TOKEN_PRIVATE_KEY` (Conversion Engine, Render) | `SECURITY_ENGINE_CONVERSION_TOKEN_PUBLIC_KEY` | yes |

The issuer is decided by **which key verifies the signature**, never by a claim. The two key
pairs **must differ**: if both variables hold the same key, tokens verify as `lab` and no receipt
is ever issued (fails closed). Neither private key ever reaches a browser: the Lab signs in a
server route, and the Conversion Engine signs server-side and removes its key from its
environment at start-up so child processes (LibreOffice, FFmpeg) never see it.

## 5. Scan receipts

**Format:** `base64url(JSON claims) "." base64url(Ed25519 signature over those exact bytes)`.
JSON is compact with sorted keys; verify the signature over the decoded payload bytes as
received, never over a re-serialization.

```json
{
  "typ": "filesmagic-scan-receipt/v1",
  "iss": "filesmagic-security-engine",
  "aud": "filesmagic-conversion-engine",
  "kid": "6393a397c964b0ca",
  "rid": "ff058dba28674ffc8fe86f7c064428d2",
  "iat": 1794791456,
  "exp": 1794791756,
  "scan_request_id": "4fd82aa4480e43ac",
  "token_jti": "1ab86ce4152a959ce51d0dc1ff1d40ee",
  "sha256": "29d46813a42650b0caba64f4c5c1d5c40afef7d7e6399b97b30a475424dc3c37",
  "size": 33558,
  "detected_format": "pdf",
  "engine": "unified",
  "engine_version": "0.2.0",
  "commit": "<40 hex>",
  "ruleset_sha256": "<64 hex>",
  "engine_ruleset_sha256": "<64 hex>",
  "scanner_versions": {"olefile": "0.47", "oletools": "0.60.2", "pypdf": "7.0.1", "yara-x": "1.21.0"},
  "scanners": ["custom", "office", "ooxml-links", "pdf", "pdf-chains", "pdf-integrity", "vba-chains", "word-fields", "yara-x", "yara-x-engine"],
  "verdict": "SAFE",
  "authorization": "allow",
  "complete": true,
  "coverage_complete": true,
  "isolation_verified": true,
  "override_eligible": false,
  "reason_codes": [],
  "findings_count": 0
}
```

| Claim | Binds |
|---|---|
| `sha256`, `size` | The bytes the **engine** hashed, not the client's claim |
| `engine`, `engine_version`, `commit`, `scanners` | Scanner engine identity and exact roster |
| `ruleset_sha256`, `engine_ruleset_sha256`, `scanner_versions` | Ruleset and scanner versions |
| `verdict`, `authorization`, `override_eligible`, `reason_codes` | Outcome and policy |
| `complete`, `coverage_complete`, `isolation_verified` | Completion, coverage, isolation status |
| `iat`, `exp` | Issued at; expires **300 s** later |
| `rid` | Unique receipt ID (single use at the Conversion Engine) |
| `kid` | Signing key ID: first 16 hex of SHA-256 of the public key's DER SubjectPublicKeyInfo |
| `token_jti`, `scan_request_id` | The request it answers; the engine log line for audit |

Reserved claims (`typ`, `iss`, `aud`, `kid`, `rid`, `iat`, `exp`) are set last by the signer and
cannot be overridden by outcome data.

### When a receipt is issued

All of the following must hold, else `receipt: null`:

1. Token issuer is `conversion`.
2. `engine == "unified"`.
3. `SECURITY_ENGINE_REQUIRE_ISOLATION=1` **and** the worker reported every required control true.
4. A valid worker report with exactly the unified roster came back.
5. **No** operational reason (§6): no worker crash, timeout, malformed report, roster mismatch,
   scanner initialization failure, internal scanner error or isolation problem.
6. A receipt key is configured.

So SAFE, SUSPICIOUS, MALICIOUS and document-caused UNABLE_TO_SCAN outcomes are signed;
operational failures never are. **MALICIOUS receipts always carry `authorization: "deny"`**
(audit/verification only); the reference verifier also rejects any receipt that is MALICIOUS
and not `deny`, or lacks `isolation_verified: true`.

### Verification procedure (Conversion Engine)

1. Compute SHA-256 and size of the **stored** upload; mint a token for exactly those; POST.
2. Non-200 → deny. Parse JSON; `receipt` missing or `null` → deny (`SCAN_UNAVAILABLE`).
3. Split on `.`; base64url-decode payload and signature; parse payload JSON.
4. Look up `kid` in the configured trusted receipt keys. Unknown → deny.
5. Ed25519-verify the signature over the payload bytes with that key. Failure → deny.
6. Check `typ`, `iss`, `aud` exactly; `iat - 30 ≤ now < exp`; `0 < exp - iat ≤ 300`.
7. Check `sha256` and `size` equal step 1's; `token_jti` equals the token just minted.
8. Check `engine == "unified"`, `isolation_verified is true`, `commit` equals the pinned
   `SECURITY_ENGINE_COMMIT`, and `scanners` equals the pinned roster.
9. Atomically record `token_jti` and `rid` as used (reject if either was already used): exactly one
   accepted receipt per minted token. Keep entries ≥ 330 s.
10. Decide **from the claims only** (§7). Ignore the response body for the decision.
11. Immediately before conversion, re-hash the file; it must still equal `sha256`.

`app/receipts.py:verify` is the reference implementation of steps 3–8: it always requires
`engine == "unified"` and `isolation_verified`, and `pins={"commit": ..., "scanners": [...],
"scanner_versions": {...}, "ruleset_sha256": ...}` makes any missing claim fail
(`RECEIPT_WRONG_TYPE`) and any different value fail (`RECEIPT_BUILD_MISMATCH`). It does not track
`token_jti` / `rid`; that store is the caller's (step 9). Tests: `tests/test_integration_v1.py`.

| `ReceiptError.code` | Meaning |
|---|---|
| `RECEIPT_MISSING` | No receipt, or longer than 8,192 characters |
| `RECEIPT_UNKNOWN_KEY` | `kid` not in the trusted set |
| `RECEIPT_INVALID_SIGNATURE` | Malformed, or the signature does not verify |
| `RECEIPT_WRONG_TYPE` | Wrong `typ`/`iss`/`aud`, missing claim, unknown authorization, isolation not verified, MALICIOUS not `deny` |
| `RECEIPT_EXPIRED` | Outside `iat - 30 ≤ now < exp`, or a lifetime over 300 s |
| `RECEIPT_FILE_MISMATCH` | `sha256` or `size` differ from the caller's bytes |
| `RECEIPT_REQUEST_MISMATCH` | `token_jti` is not the caller's token |
| `RECEIPT_BUILD_MISMATCH` | Not the unified engine, or a pinned build value differs |

## 6. Reason codes

Stable, machine-readable, upper snake case. `reasons[].category` and `override_eligible` come
from these tables (`app/decision/__init__.py`); **any code not in the eligible table, including
one added by a later release, is never eligible.**

### Document reasons, override-eligible (`category: "document"`, `override_eligible: true`)

| Code | Meaning |
|---|---|
| `PDF_ENCRYPTED_CONTENT_UNAVAILABLE` | Page content requires a password |
| `PDF_CONTENT_FILTER_UNSUPPORTED` | Page content uses a filter the engine does not decode |
| `PDF_CONTENT_DECODE_FAILED`, `PDF_CONTENT_LZW_DECODE_FAILED` | A page-content stream is damaged |
| `PDF_CONTENT_STREAM_UNRESOLVED` | A page `/Contents` value is not a stream |
| `PDF_CONTENT_STREAM_LIMIT`, `PDF_CONTENT_TOTAL_LIMIT` | Over 10,000 content streams / 32 MiB decoded |
| `PDF_PARSER_REPAIRED`, `PDF_STRUCTURE_REPAIRED`, `PDF_CHAIN_PARSER_REPAIRED` | Readable only after structural repair |
| `PDF_ATTACHMENT_COVERAGE_INCOMPLETE` | Not every attachment could be inspected |
| `CUSTOM_PDF_C1_COVERAGE_INCOMPLETE` | Some object streams were not inspected |
| `DOCUMENT_MALFORMED` | A scanner rejected the file's syntax (`error_kind: malformed_input`) |
| `DOCUMENT_STRUCTURE_UNSUPPORTED` | Structure invalid, password-protected or over analysis limits (`error_kind: invalid_structure`) |

### Document reasons, never eligible (`category: "document"`, `override_eligible: false`)

| Code | Meaning |
|---|---|
| `UNSUPPORTED_FILE_TYPE` | No scanner applies to the file |
| `ANALYSIS_INCOMPLETE_UNCLASSIFIED` | UNABLE_TO_SCAN with no classified reason, or an unknown code |

### Operational reasons, never eligible, never receipted (`category: "operational"`)

| Code | Meaning |
|---|---|
| `WORKER_CRASHED` | Worker exited abnormally (incl. native crash) |
| `WORKER_TIMEOUT` | Worker exceeded its wall-clock limit (30 s) |
| `WORKER_INVALID_REPORT` | Worker output malformed or over 1 MiB |
| `WORKER_FAILED` | Other worker failure |
| `SCANNER_ROSTER_MISMATCH` | Worker reported a scanner set other than the engine's |
| `SCANNER_NOT_READY` | A scanner failed to initialize (e.g. YARA-X rules did not compile) |
| `SCANNER_INTERNAL_ERROR` | A scanner hit an unexpected error (possible bug), or YARA-X failed for any reason (it reads raw bytes, so its failures are never the document's). Also what a PDF pypdf cannot open at all produces: `pdf-integrity` declares no malformed causes, so that failure is "unexpected". Fail-closed; the user explanation blames neither side |
| `ISOLATION_NOT_ENFORCED` | `SECURITY_ENGINE_REQUIRE_ISOLATION` is not `1` |
| `ISOLATION_UNVERIFIED` | A required isolation control was not reported true, or the strict worker refused to analyse |

Authentication, token, size, rate and busy failures are HTTP errors (§3), not reasons.

The worker's generic coverage codes `SCANNER_ANALYSIS_FAILED` and `PDF_INTEGRITY_ANALYSIS_FAILED`
stay in `coverage_issues` but are not repeated as reasons: the failed scanner's `error_kind`
classifies them instead.

## 7. Verdict and authorization policy

Applied in order (`app.decision.classify`):

| # | Condition | `authorization` | Receipt |
|---|---|---|---|
| 1 | `verdict == MALICIOUS` | `deny`, permanently, never overridable | signed (if no operational reason) |
| 2 | Any operational reason | `deny` | **none** |
| 3 | Any reason not override-eligible | `deny` | signed |
| 4 | `verdict == SAFE` | `allow` | signed |
| 5 | `SUSPICIOUS`, or `UNABLE_TO_SCAN` whose reasons are all document-eligible | `consent_required` | signed |

| Verdict | Frontend | Conversion Engine |
|---|---|---|
| SAFE | Proceed automatically | Convert on a verified `allow` receipt |
| SUSPICIOUS | Show findings + explanation; require explicit consent | Convert only on a verified `consent_required` receipt **and** a recorded user consent for that `rid` |
| MALICIOUS | Explain; offer no override | Never convert |
| UNABLE_TO_SCAN, `consent_required` | Explain each reason; offer consent | As SUSPICIOUS |
| UNABLE_TO_SCAN, `deny` | Explain; operational → "try again later"; no override | Never convert |

### Consent flow

1. The Conversion Engine scans, verifies the receipt and finds `consent_required`. It keeps
   `{rid, sha256, size, exp, reasons, findings}` **server-side** against the stored upload and
   returns to the frontend a `SCAN_CONSENT_REQUIRED` error with the sanitized findings, reasons
   and explanations and an opaque consent handle (e.g. the `rid`). It does not mark `rid` used yet.
2. The frontend shows the findings and reasons, and asks for an explicit action ("Convert anyway").
3. The frontend calls the conversion again with the handle. The Conversion Engine looks up the
   stored receipt (never accepts one from the client), checks `now < exp`, marks `rid` used,
   re-hashes the file (must equal `sha256`), logs the consent (`rid`, `scan_request_id`, time,
   session), and converts.
4. Receipt expired (5 min) → rescan with a new token. The new receipt must again be `consent_required`
   and the user must consent again.

The frontend never sends a verdict, hash or receipt that the Conversion Engine trusts.

## 8. Configuration

### Security Engine (Render, protected environment)

| Variable | Value | Notes |
|---|---|---|
| `SECURITY_ENGINE_CONVERSION_TOKEN_PUBLIC_KEY` | base64 DER SPKI Ed25519 | **New.** Public half of the Conversion Engine token pair |
| `SECURITY_ENGINE_RECEIPT_PRIVATE_KEY` | base64 DER PKCS#8 Ed25519 | **New, secret.** Removed from the process environment at start-up; never passed to workers |
| `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` | base64 DER SPKI | Lab token key. Leave **unset** on a service with no Lab |
| `SECURITY_ENGINE_REQUIRE_ISOLATION` | `1` | Required for receipts |
| `SECURITY_ENGINE_RESEARCH_ENGINES` | `1` | Enables `engine=unified` (the flag's name predates this contract; see §12) |
| `SECURITY_ENGINE_PUBLIC_UNIFIED_ONLY` | `1` | Recommended in production: offer only the unified engine |
| `SECURITY_ENGINE_COMMIT` | full 40-hex SHA | Optional; Render's `RENDER_GIT_COMMIT` is used otherwise |
| `SECURITY_ENGINE_CORS_ORIGINS` | unset or exact Lab origin | The Conversion Engine is server-to-server and needs no CORS |
| `SECURITY_ENGINE_MAX_CONCURRENT_SCANS` | `1` | Sized for 512 MB |

### Conversion Engine (Render, protected environment)

| Variable | Value |
|---|---|
| `SECURITY_ENGINE_URL` | `https://filesmagic-security-engine.onrender.com` |
| `SECURITY_ENGINE_COMMIT` | Pinned full SHA of the deployed Security Engine build |
| `SECURITY_ENGINE_TOKEN_PRIVATE_KEY` | base64 DER PKCS#8 Ed25519 (secret): private half of the conversion token pair |
| `SECURITY_ENGINE_RECEIPT_PUBLIC_KEYS` | Comma-separated base64 DER SPKI Ed25519 public keys trusted for receipts. `kid` is derived from each key, never configured |

### Key generation and key IDs

Use `filesmagic-engine`'s `scripts/scan_keys.py` once per pair, in a folder outside every repository:

```
python scripts/scan_keys.py new <dir-conversion-token>   # private.txt → Conversion Engine SECURITY_ENGINE_TOKEN_PRIVATE_KEY
                                                         # public.txt  → Security Engine SECURITY_ENGINE_CONVERSION_TOKEN_PUBLIC_KEY
python scripts/scan_keys.py new <dir-receipt>            # private.txt → Security Engine SECURITY_ENGINE_RECEIPT_PRIVATE_KEY
                                                         # public.txt  → Conversion Engine SECURITY_ENGINE_RECEIPT_PUBLIC_KEYS
python scripts/scan_keys.py check <dir-receipt>          # prints the key ID; must equal /health receipt_key_id
```

Paste values only in the Render dashboard as secrets; never print, commit or pass them on a
command line. Delete the folders afterwards. The receipt public key is not secret, but it must
reach the Conversion Engine through its protected configuration, never fetched from the
Security Engine at run time.

### Receipt key rotation

1. Generate a new receipt pair. Add the new public key to `SECURITY_ENGINE_RECEIPT_PUBLIC_KEYS`
   (both keys trusted) and redeploy the Conversion Engine.
2. Replace `SECURITY_ENGINE_RECEIPT_PRIVATE_KEY` on the Security Engine; confirm `/health`
   `receipt_key_id` shows the new ID.
3. After ≥ 330 s (receipt lifetime + skew), remove the old public key from the Conversion Engine.

The Security Engine signs with one key at a time. An emergency revocation is step 3 done
immediately. Rotating the conversion token pair is the same, in reverse (public key to the
Security Engine first). Neither rotation is part of this change.

## 9. Readiness (`GET /health`)

```json
{"status": "ok", "service": "filesmagic-security-engine", "scanners_registered": 4, "scanners_ready": 4,
 "auth_configured": false, "engines": ["unified"], "default_engine": "unified", "commit": "<sha>",
 "conversion_auth_configured": true, "receipt_key_id": "6393a397c964b0ca",
 "isolation_required": true, "max_upload_bytes": 10485760, "ready_for_conversion": true}
```

`ready_for_conversion` is true only with a conversion token key, a receipt key, strict isolation,
Lab and conversion token keys that differ, the unified engine enabled and every unified scanner loaded. Before enabling the gate, the
Conversion Engine release check must see `ready_for_conversion: true`, the pinned `commit`
and the expected `receipt_key_id`. `/health` cannot prove isolation works on the host: only a
real scan's `isolation_verified` does (the probe in §10).

## 10. Integration example (Conversion Engine, Python)

```python
import base64, hashlib, json, secrets, time, urllib.request
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key

ROSTER = ["custom", "office", "ooxml-links", "pdf", "pdf-chains", "pdf-integrity",
          "vba-chains", "word-fields", "yara-x", "yara-x-engine"]
b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
unb64 = lambda s: base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def trusted_receipt_keys(env_value: str) -> dict:
    keys = {}
    for item in filter(None, (v.strip() for v in env_value.split(","))):
        key = load_der_public_key(base64.b64decode(item))
        kid = hashlib.sha256(key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:16]
        keys[kid] = key
    return keys

def scan(data: bytes, token_key, url: str) -> tuple[dict, str]:
    now = int(time.time())
    claims = {"aud": "filesmagic-security-engine/scan", "iat": now, "exp": now + 120,
              "jti": secrets.token_hex(16), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    payload = json.dumps(claims, separators=(",", ":")).encode()
    req = urllib.request.Request(f"{url}/scan?engine=unified", data=data, method="POST", headers={
        "Authorization": f"Bearer {b64(payload)}.{b64(token_key.sign(payload))}",
        "Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=60) as r:          # non-200 raises: deny
        return json.loads(r.read(1024 * 1024 + 1)), claims["jti"]

def verify_receipt(receipt, trusted: dict, data: bytes, jti: str, pinned_commit: str) -> dict:
    payload_b64, sig_b64 = receipt.split(".")                   # any exception: deny
    payload = unb64(payload_b64)
    claims = json.loads(payload)
    trusted[claims["kid"]].verify(unb64(sig_b64), payload)      # KeyError / InvalidSignature: deny
    now = time.time()
    assert claims["typ"] == "filesmagic-scan-receipt/v1"
    assert claims["iss"] == "filesmagic-security-engine" and claims["aud"] == "filesmagic-conversion-engine"
    assert claims["iat"] - 30 <= now < claims["exp"] and 0 < claims["exp"] - claims["iat"] <= 300
    assert claims["sha256"] == hashlib.sha256(data).hexdigest() and claims["size"] == len(data)
    assert claims["token_jti"] == jti and claims["engine"] == "unified"
    assert claims["isolation_verified"] is True and claims["commit"] == pinned_commit
    assert claims["scanners"] == ROSTER
    assert claims["authorization"] in ("allow", "consent_required", "deny")
    return claims

def admit(data: bytes, token_key, url, trusted, pinned_commit, used_rids) -> str:
    """'allow', 'consent_required' (with the claims stored server-side) or raises (deny)."""
    try:
        body, jti = scan(data, token_key, url)
        claims = verify_receipt(body.get("receipt"), trusted, data, jti, pinned_commit)
    except Exception:
        raise ScanUnavailable()                                 # never convert
    if claims["verdict"] == "MALICIOUS" or claims["authorization"] == "deny":
        raise ScanBlocked(body.get("explanation"), body.get("reasons"))
    if claims["authorization"] == "consent_required":
        store_pending_consent(claims, body["findings"], body["reasons"])  # server-side, keyed by rid
        return "consent_required"
    if not used_rids.add_if_absent(claims["rid"], ttl=330):
        raise ScanUnavailable()
    return "allow"
```

Production code should replace `assert` with explicit checks (assertions vanish under `python -O`),
like `app/receipts.py:verify`. The existing draft gate (`filesmagic-engine` PR #1, `app/scan.py`)
must be updated to this contract: 10-scanner roster including `pdf-integrity`, decisions from
receipt claims, `rid` single use, the consent flow, and the new pinned commit.

## 11. Deployment prerequisites

Nothing here has been deployed. Before production:

1. **Approval** of this release and of every step below.
2. **Accuracy regression** of this exact build over the 252-sample corpus
   (`evaluation/dependency_regression.py` against the 90718ff and 840a300 baselines), because the
   pdf-integrity scanner and pypdf 7.0.1 were each validated alone, not together.
3. **Staging first:** deploy to `filesmagic-security-engine-staging` with both new keys; send one
   conversion-token probe scan (`scan_keys.py probe` with the conversion token pair, extended to
   verify the receipt with `app/receipts.py:verify`); confirm `isolation_verified: true` and a
   receipt that verifies; run the Lab acceptance run (`evaluation/lab_acceptance.py`) to confirm
   the Lab still works.
4. **Plan:** Starter (0.5 CPU / 512 MB, $7/month) or larger. Free instances sleep (cold start
   about 22 s on staging) and ran heavy PDF work 13–16× slower than local; the Conversion Engine's
   60 s timeout would then turn slow scans into denials.
5. **Isolation on the production host:** unprivileged user + network namespaces must work
   there. `/health` cannot show this; a probe scan's `isolation_verified` can.
6. **Conversion Engine** updated to §5/§7/§10 and rehearsed end to end (scan-gate-e2e).
7. Frontend copy for SUSPICIOUS / UNABLE_TO_SCAN consent and denials approved.

## 12. Known limits, risks and conflicts

- **25 MiB input ceiling, requires load validation before enforcement.** The HTTP API,
  isolated worker and Conversion Engine now use the same 26,214,400-byte limit, including
  declared-length and streamed-size enforcement. This preserves the existing 25 MB user limit.
  Historical 25 MB tests on `90718ff` found 2 of 10 benign files flagged SUSPICIOUS by a
  JavaScript indicator and peak worker memory of 278 MB against a 320 MB RLIMIT_DATA.
  Raising the byte ceiling is **not** evidence that every 25 MB file can be scanned.
  Test actual 25 MiB PDFs and Office files under a 512 MB host constraint and the
  strict worker isolation profile before enabling `SECURITY_MODE=enforce`. Operational
  worker failures must remain unreceipted and fail closed.
- **Research flag in production (conflict).** The README calls `SECURITY_ENGINE_RESEARCH_ENGINES`
  research-only, but the validated production scanner is the unified engine that flag enables.
  Kept the flag rather than renaming it, to stay compatible with the Lab, staging and the draft gate.
  This is documented here and in the README; renaming it is a separate change.
- **Single instance; replay limits.** Token replay (`jti`), failure counters and the busy counter are
  in process memory. Run exactly one uvicorn process and one instance (the Dockerfile does). Scaling
  out needs a shared store first. After an engine restart, a token captured in its last 120 s can be
  used once more; it yields at most another receipt for the **same bytes and the same `token_jti`**,
  which the Conversion Engine refuses (one receipt per token, step 9). Receipts themselves are
  bearer statements valid 300 s: single use is enforced only by the Conversion Engine's `rid` store.
- **Worker report trust.** Verdict, findings and isolation status come from the worker process that
  parsed the document. A parser exploit that takes over the worker could forge its report, and so
  the receipt's content. Isolation limits what such a worker can reach, not what it reports.
- **Shared egress rate limit.** Failed-auth throttling is per client address (20/min). Another Render
  service sharing the Conversion Engine's outbound address could exhaust it (`429 RATE_LIMITED`);
  the result is denial (fail closed), not bypass.
- **Concurrency 1.** A second simultaneous scan gets `429 ENGINE_BUSY`; the Conversion Engine queues
  locally (its single-scan lock).
- **Isolation is not a full sandbox.** The worker shares the API's user and container; a native
  parser exploit could bypass the audit hook (docs/malware-research-readiness.md). The receipt key
  is in API memory only, never in the worker's environment, but a full API-process compromise
  could sign receipts. Containment: short lifetime, `rid` single use, rotation.
- **Override risk.** Encrypted, damaged or oversized documents are eligible for consent by design
  (the product requirement). An attacker can craft such a file to reach the consent dialog; the
  UI must state plainly that the file was **not** fully inspected.
- **SAFE is not proof of harmlessness.** The engine detects known indicators only.
- **Receipt key misconfiguration fails closed.** No receipt key, same key for both issuers, or
  isolation off → no receipts → no conversions.
