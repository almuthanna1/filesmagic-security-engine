# Staging acceptance: commit `7b4f838` (2026-11-07/08)

| Item | Value |
|---|---|
| Engine (Render staging) | https://filesmagic-security-engine-staging.onrender.com, Free plan, `SECURITY_ENGINE_RESEARCH_ENGINES=1`, strict isolation required; `/health` commit `7b4f83832e5fdeb1b8a6d58079bbd7640c54dbd8`, engines `reference`, `unified` |
| Lab (Vercel staging) | https://filesmagic-security-lab-staging.vercel.app, built from a clean checkout of `7b4f838` |
| Token limit | unchanged: 12 tokens per 15 minutes; every run paced under it |
| Fixtures | the 16 inert evaluation cases plus clean XLSX, clean PPTX and a truncated PDF (`evaluation.lab_acceptance.items()`) |

## HTTP acceptance (`python -m evaluation.lab_acceptance`)

| Report | UTC | Result |
|---|---|---|
| `batch0` | 11-07 20:41 | 12/12 |
| `batch1`, `batch2`, `batch3` | 20:58, 21:15, 11-08 01:59 | 2 of 26 ran; the rest were refused 429 because a duplicate run shared the token window (operator error, not a product defect) |
| `failures` | 02:01 | 4/4: oversized file 413 at the token route and the engine, unknown engine 400, bad token 401 |
| `retry0`, `retry1` | 02:20, 02:37 | 24/24: only the refused (case, engine) pairs, 12 tokens per window |

Combined: 38/38 scans (19 fixtures x 2 engines) match the frozen evaluation (verdict, non-INFO rules,
scanner statuses) or the expected verdict, CORS allows the Lab origin, each response describes the
uploaded bytes and names the requested engine, and every scan reports `isolation_missing: []`.

## Staging UI (Chrome, isolated profile)

- `7b4f838-staging-ui-compare-5a.png`: Compare both on `5a-pdf-auto-js-unrelated-attachment.pdf`:
  original MALICIOUS, unified SUSPICIOUS, same SHA-256, both commit `7b4f838`, no missing controls.
- Truncated PDF, unified engine: UNABLE_TO_SCAN, three scanners failed with their parse errors.
- `7b4f838-staging-ui-history.{png,csv,json}`: the History page and its CSV/JSON exports of those
  three records (captured in the page, not downloaded).
