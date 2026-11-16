# Handoff: integrating the Security Engine into FilesMagic (contract v1)

**For:** the developer of `almuthanna1/filesmagic-engine` (Conversion Engine) and `almuthanna1/filesmagic`
(website). **Contract:** [security-integration-v1.md](security-integration-v1.md) is authoritative; this file
says what to build against it. **Security Engine build:** branch `feature/production-scan-integration-v1`,
PR #23, not yet deployed anywhere.

Nothing in this handoff has been changed in those repositories.

## 1. What changes compared with the earlier gate (filesmagic-engine PR #1)

PR #1 (`feature/security-scan-gate`, origin head `9dbf76e`; a local worktree also has an unpushed
`e7a1916`) predates this contract. It decides from the **response body**, expects the **9-scanner** roster
of `90718ff`, and has no consent path. Required changes:

| Area | PR #1 today | Required |
|---|---|---|
| Decision source | Response body (`verdict`, `complete`, `isolation_*`) | **Receipt claims only** (§3). The body is for display |
| Scanner roster | 9 names | The 10 names of §3, including `pdf-integrity` |
| Build pin | `versions.commit` prefix | Receipt `commit` == `SECURITY_ENGINE_COMMIT` (full 40 hex), plus roster |
| Token key | `SECURITY_ENGINE_TOKEN_PRIVATE_KEY` (verified by SE's Lab variable) | Same variable name, but its public half goes into SE's **`SECURITY_ENGINE_CONVERSION_TOKEN_PUBLIC_KEY`** (a key pair of its own, never the Lab's) |
| Receipt keys | none | `SECURITY_ENGINE_RECEIPT_PUBLIC_KEYS` (§6) |
| Verdicts | SAFE converts; everything else → `SCAN_BLOCKED` / `SCAN_UNAVAILABLE` | `allow` converts; `consent_required` → consent flow (§4); `deny` → blocked/unavailable |
| Single use | none | One accepted receipt per minted token (`token_jti`) and per `rid` |

## 2. Endpoints the Conversion Engine calls

| Call | When | Notes |
|---|---|---|
| `GET {SECURITY_ENGINE_URL}/health` | At start-up and every few minutes (not per request) | Require `ready_for_conversion: true`, `commit == SECURITY_ENGINE_COMMIT`, `receipt_key_id` in the trusted set, `max_upload_bytes == 10485760`. If not, report the gate unavailable in your own `/health` and refuse uploads with `SCAN_UNAVAILABLE` |
| `POST {SECURITY_ENGINE_URL}/scan?engine=unified` | Once per stored upload, before any parser touches it | Body = the exact stored bytes; `Authorization: Bearer <token>`; `Content-Type: application/octet-stream`; no `X-Filename` needed |

No other endpoint. Never send a client-supplied hash, verdict or filename as a decision input.

## 3. Per-upload algorithm (`admit`)

1. Store the upload (streamed, with the size limit). **Refuse > 10,485,760 bytes before scanning** (`FILE_TOO_LARGE`).
2. `digest = sha256(stored bytes)`, `size = len(stored bytes)`.
3. Mint a token: `{"aud": "filesmagic-security-engine/scan", "iat": now, "exp": now + 120, "jti": 32 random hex, "sha256": digest, "size": size}`,
   compact JSON, Ed25519-sign the bytes, `base64url(payload) + "." + base64url(signature)` (unpadded). Keep `jti`.
4. POST with a 60 s timeout, no redirects, response capped at 1 MiB. Hold the process-wide scan lock
   (the engine runs one scan at a time; `429 ENGINE_BUSY` otherwise).
5. Map HTTP errors (contract §3): `413` → `FILE_TOO_LARGE`; `429` → `SERVER_BUSY`; anything else non-200,
   transport error or unparseable JSON → `SCAN_UNAVAILABLE`. Never retry with the same token.
6. Verify `body["receipt"]` (contract §5). The checks, all required:
   - signature by a trusted `kid`;
   - `typ` / `iss` / `aud` exact;
   - `iat - 30 <= now < exp` and `exp - iat <= 300`;
   - `sha256` / `size` equal step 2;
   - `token_jti == jti`;
   - `engine == "unified"`, `isolation_verified is True`;
   - `commit == SECURITY_ENGINE_COMMIT`;
   - `scanners == ["custom", "office", "ooxml-links", "pdf", "pdf-chains", "pdf-integrity", "vba-chains", "word-fields", "yara-x", "yara-x-engine"]`.

   A missing (`null`) or failing receipt → `SCAN_UNAVAILABLE`. The reference implementation is
   `app/receipts.py:verify(..., token_jti=jti, pins={"commit": ..., "scanners": [...]})` in the Security Engine
   repository; port it with explicit checks (no `assert`).
7. Record `token_jti` as used (accept exactly one receipt per token) and act on `claims["authorization"]`:
   - `allow` → record `rid` as used, convert.
   - `consent_required` → §4.
   - `deny` → `SCAN_BLOCKED` if `claims["verdict"] in ("MALICIOUS", "SUSPICIOUS")` or any reason is a
     document reason; `SCAN_UNAVAILABLE` never occurs here (operational failures have no receipt).
8. Immediately before the conversion handler: re-hash the file; it must equal `claims["sha256"]`
   (`verify_unchanged`, already in PR #1).

### Operational failure vs override-eligible incomplete analysis

You never classify this yourself. The Security Engine does:

- **Operational failure:** no receipt at all. Worker crash or timeout, malformed worker report, scanner not
  ready, scanner internal error, isolation not enforced or unverified, outage, or authentication failure.
  → `SCAN_UNAVAILABLE`, no consent offered, ever.
- **Eligible incomplete analysis:** a receipt with `authorization: "consent_required"` and every
  `reason_codes` entry in the contract's eligible table. Example codes: encrypted content, damaged or
  unsupported structure, analysis limits.
- **Anything else:** `deny`.

Do not maintain your own list of eligible codes; trust `authorization` from the verified receipt.

## 4. User acknowledgement without a bypass

1. On `consent_required`, store server-side, keyed by `rid`:
   - the claims;
   - the response's `findings`, `reasons` and `explanation`;
   - the upload's workspace path;
   - the session.

   Do **not** mark `rid` used yet. Respond with a new error code, **`SCAN_CONSENT_REQUIRED`** (HTTP 409), carrying:
   - `consent_id`: an opaque random handle mapped to `rid`;
   - `expires_at` = `claims["exp"]`;
   - `findings`: severity, description, rule_id;
   - `reasons`: code, explanation;
   - `explanation`.
2. The website renders all text **as text** (it can quote document content), states that the file was not
   fully inspected / may be risky, and offers one explicit action ("Convert anyway").
3. On that action, the client calls the same route again with `consent_id` (and the same session). The
   Conversion Engine:
   - looks up the stored entry, and refuses if it is missing, expired (`now >= exp`), or belongs to another session;
   - atomically marks `rid` used;
   - re-hashes the stored file against `claims["sha256"]`;
   - logs `{rid, scan_request_id, verdict, reason_codes, session, time}`;
   - converts.

   It never accepts a receipt, verdict or hash from the client.
4. Expired consent → rescan with a new token; a new `consent_required` needs a new acknowledgement.
5. `MALICIOUS` and every `deny` produce no `consent_id`.

Keep pending-consent entries ≤ 330 s and delete the workspace on expiry, as for any abandoned upload.

## 5. Merge and other multi-file operations

- Scan **each input file separately** (PR #1's `_receive` already does), each with its own token and receipt,
  serially under the scan lock.
- The operation runs only if every file is `allow`, or `consent_required` and acknowledged. Any `deny`
  or failure rejects the whole operation and names which file.
- Consent covers the operation's whole set: return one `SCAN_CONSENT_REQUIRED` listing every
  `consent_required` file (each with its own `consent_id`), and require one action that acknowledges all of them.
- Merge's aggregate limit stays as PR #1 has it (4 × 10 MB). Each file is still ≤ 10 MB.
- **Timeout:** N files take N sequential scans. On a sleeping or 0.1-CPU instance, a cold start (22 s) plus
  several 6–7 s scans can exceed the website's request timeout. Use the Starter plan (§7), and set the merge
  route's client timeout to ≥ 30 s + 10 s × files.

## 6. Configuration

| Variable (Conversion Engine, Render, secret where marked) | Value |
|---|---|
| `SECURITY_ENGINE_URL` | `https://filesmagic-security-engine.onrender.com` (production) |
| `SECURITY_ENGINE_COMMIT` | Full 40-hex SHA of the deployed Security Engine build |
| `SECURITY_ENGINE_TOKEN_PRIVATE_KEY` (secret) | Private half of the **conversion** token pair; removed from the environment at start-up (PR #1 does this) |
| `SECURITY_ENGINE_RECEIPT_PUBLIC_KEYS` | Comma-separated base64 DER SPKI receipt public keys; `kid` derived from each |

| Variable (Security Engine, Render) | Value |
|---|---|
| `SECURITY_ENGINE_CONVERSION_TOKEN_PUBLIC_KEY` | Public half of the conversion token pair |
| `SECURITY_ENGINE_RECEIPT_PRIVATE_KEY` (secret) | Receipt signing key |
| `SECURITY_ENGINE_REQUIRE_ISOLATION` | `1` |
| `SECURITY_ENGINE_RESEARCH_ENGINES` / `SECURITY_ENGINE_PUBLIC_UNIFIED_ONLY` | `1` / `1` |
| `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` | Unset on production (no Lab there); if set, it must differ from the conversion key |

Generate both pairs with `filesmagic-engine/scripts/scan_keys.py new <dir>` (outside every repository); confirm
with `check` that the receipt key ID equals the Security Engine's `/health` `receipt_key_id`.

## 7. Readiness, timeouts, capacity

- Upload ceiling **10 MB** everywhere (API, website `UPLOAD_LIMITS`, app). 25 MB stays blocked (contract §12).
- Security Engine limits:
  - 60 s to receive the body;
  - 30 s worker wall clock;
  - 20 s worker CPU;
  - one scan at a time;
  - 32 open connections.

  The Conversion Engine's 60 s request timeout matches. Increase it only together with the engine's limits.
- Free plan: the instance sleeps (22 s first request) and has 0.1 CPU. Use **Starter (0.5 CPU / 512 MB)** for the
  Security Engine before enabling the gate (readiness report §6).
- The engine is single-instance by design (in-memory token replay store). Do not scale it horizontally.

## 8. Unsupported formats

- The Security Engine's coverage is PDF and Office (OOXML, OLE2). For other bytes, only the YARA-X signature
  scanners apply, and a SAFE there means only "no known signature".
- The receipt's `detected_format` is from magic bytes: `pdf`, `ole2`, `zip`, `rtf` or `unknown`.
- A document route must check `detected_format` against what it accepts and refuse a mismatch with
  `UNSUPPORTED_FORMAT`:
  - PDF routes: `pdf`.
  - DOCX/XLSX/PPTX: `zip`.
  - DOC/XLS/PPT: `ole2`.

  Do not convert a "PDF" whose bytes the engine did not identify as PDF.
- Image routes (JPG/PNG/WebP → PDF) can keep scanning through the gate (YARA-X only). The product decision
  to state that images get signature checks only belongs in the public copy.
- A receipt with `UNSUPPORTED_FILE_TYPE` is `deny` → `UNSUPPORTED_FORMAT`.

## 9. Compatibility with existing clients

- Existing error codes keep their meaning: `SCAN_BLOCKED` (422) and `SCAN_UNAVAILABLE` (503).
- `SCAN_CONSENT_REQUIRED` is new. Clients that do not implement it (the current iOS app; older website builds)
  must not be shown a consent flow they cannot complete. Offer consent only when the request declares
  support (e.g. header `X-FilesMagic-Scan-Consent: 1`). Otherwise map `consent_required` → `SCAN_BLOCKED`
  with a message that the file needs review on the website.
- No response field the website or app reads today changes. The Security Engine's own `/scan` and `/health`
  additions are additive.

## 10. Website (`filesmagic`) tasks

- Handle `SCAN_CONSENT_REQUIRED`: a dialog listing findings (severity, description) and reason explanations,
  rendered as plain text, plus one explicit "Convert anyway" action; send the `consent_id` back.
- No override UI for `SCAN_BLOCKED` with MALICIOUS, or for `SCAN_UNAVAILABLE` (say "try again later").
- Keep 10 MB in `UPLOAD_LIMITS`, the help text and `llms.txt`. Public copy: SAFE = "no known threats detected",
  never "safe" or "virus-free" as a guarantee. **Copy needs approval.**

## 11. Tests the downstream PRs must add

- `allow` converts; `consent_required` without consent never converts; with a valid `consent_id` converts once.
- A replayed `consent_id`, an expired one, or one from another session never converts.
- `deny` and MALICIOUS never convert, with or without `consent_id`.
- `null` receipt, tampered receipt, wrong `kid`, wrong commit or roster, wrong `token_jti`, or a receipt
  for other bytes → `SCAN_UNAVAILABLE`.
- Merge with one `deny` file rejects the whole merge; with one `consent_required` file needs consent.
- A file changed between scan and conversion → refused (`verify_unchanged`).
- The end-to-end rehearsal (`scan-gate-e2e.yml`), updated to this build and its 10-scanner roster.
