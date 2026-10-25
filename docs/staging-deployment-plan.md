# Benign-only staging deployment plan (Phase C)

Status: **approved with one change: Render Free instead of Starter** (Phase C1). Resources are
created step by step with explicit approval; see the phase reports for what exists. Source: branch `security/malware-research-hardening`, commit `90453e4` (CI run
40147894857: 274 passed, 0 failed, 0 skipped).

Scope: a separate staging Security Engine (Render) and Security Lab (Vercel) for **benign and
synthetic files only**. The live Security Lab, the live Render Security Engine, the FilesMagic
website and the FilesMagic conversion backend are not touched. Nothing is merged into `main`.

## 1. Target architecture

```
Admin browser (isolated VM)
   │ HTTPS
   ▼
Vercel project  filesmagic-security-lab-staging   (NEW, CLI-deployed, not Git-connected)
   │ /api/session, /api/scan-token  (LAB_* secrets, Production env of the staging project)
   │ browser uploads directly to ▼
Render workspace  "FilesMagic Research"  (NEW Hobby workspace, own private network)
   └─ web service  filesmagic-security-engine-staging  (Docker, region Virginia, branch
      security/malware-research-hardening, Auto-Deploy off)

Untouched: Vercel project filesmagic-security-lab (live Lab) · Render workspace "Personal
Projects" (live engine + FilesMagic production backend, Oregon)
```

Why each separation:

- **New Render workspace**: Render private networks are scoped to one workspace and one region,
  so the staging engine cannot reach the FilesMagic production backend over the private
  network. A different region (Virginia instead of Oregon) adds a second, independent
  separation and is close to Vercel's default function region (Washington, D.C., `iad1`).
- **New Vercel project, CLI-deployed**: `frontend/vercel.json` disables Git deployments of
  `security/malware-research-hardening` for *every* project that builds from `frontend/`, so a
  Git-connected staging project could not build the hardening branch either. A project with no
  Git connection, deployed with `vercel deploy --prod` from a clean checkout of `90453e4`,
  avoids that and cannot be redeployed by any push. The live project keeps its settings.

## 2. Render: separate research environment

### 2.1 Workspace

| Setting | Value |
|---------|-------|
| Workspace | New **Hobby** workspace, e.g. "FilesMagic Research" (Render allows up to five Hobby workspaces per user) |
| Members | Only you (Hobby workspaces cannot add members) |
| GitHub access | Connect the Render GitHub app **to this repository only** |
| Billing | Payment method needed only for a paid instance type |

### 2.2 Web service

Create it manually ("New → Web Service"), **not** from `render.yaml` (a Blueprint would reuse
the production service name and adds nothing here).

| Setting | Value | Reason |
|---------|-------|--------|
| Name | `filesmagic-security-engine-staging` | URL `https://filesmagic-security-engine-staging.onrender.com` (adjust everywhere if Render assigns a suffix) |
| Runtime | Docker, Dockerfile path `./Dockerfile`, context `.` | Image pins `python:3.11-slim`; runs as non-root `engine` (uid 10001); verified in CI |
| Repository / branch | this repo / `security/malware-research-hardening` | Commit `90453e4` |
| Region | Virginia (US East) | Not Oregon (see §1) |
| Instance type | **Free** ($0, 0.1 CPU, 512 MB) | Approved to avoid monthly cost. Sleeps after 15 min idle (first request ~1 min; open `/health` before scanning so a token does not expire during the wake-up; the Lab also retries once). 0.1 CPU makes each worker start slower (seconds). 750 free instance hours per workspace per month |
| Upgrade path | Starter (`0.5c-512mb`, about $7/month) | Only with separate approval, if Free proves too slow or unstable |
| Auto-Deploy | **Off** | Deploy manually only |
| Pull-request previews | Off (default) | |
| Health check path | `/health` | Returns `auth_configured`, `scanners_ready` |

### 2.3 Environment variables (Render staging service)

| Variable | Staging value | Notes |
|----------|---------------|-------|
| `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` | staging public key (§4) | Required; without it every scan is refused |
| `SECURITY_ENGINE_CORS_ORIGINS` | `https://filesmagic-security-lab-staging.vercel.app` | Exact staging origin only; never the live Lab, never `*` |
| `SECURITY_ENGINE_MAX_CONCURRENT_SCANS` | `1` | 512 MB instance |
| `SECURITY_ENGINE_WORKER_MEMORY_MB` | `256` | API ≈ 70 MiB + one worker; leaves headroom under 512 MB. Raise only after reading Render memory metrics |
| `SECURITY_ENGINE_WORKER_TIMEOUT_SECONDS` | `30` | Temporarily `1` for the timeout test (§6) |
| `SECURITY_ENGINE_REQUIRE_ISOLATION` | see §2.4 | |

No other variables. In particular no FilesMagic production secrets, database URLs or API keys.

### 2.4 Strict isolation mode, tested safely

Network namespaces are **not** assumed: CI showed `network_namespace=false` inside Docker's
default sandbox, and Render runs Docker containers.

1. First deploy with `SECURITY_ENGINE_REQUIRE_ISOLATION` **unset**. Scan the benign DOCX and
   record the `isolation` block (expected: `process`, `rlimits`, `audit_hook` true;
   `network_namespace` false).
2. Set `SECURITY_ENGINE_REQUIRE_ISOLATION=1`, redeploy, scan the same benign DOCX.
   Expected if the namespace is unavailable: verdict `UNABLE_TO_SCAN`, every scanner `failed`
   with `required isolation unavailable: network_namespace`, and nothing analysed.
3. **Preserve the evidence**: export that `/evaluation` record (JSON + CSV), save the Render log
   line (`scan request_id=…`) and the response, and record the result in the readiness report as
   "strict isolation fails on Render: network namespace unavailable".
4. For the remaining **benign** acceptance tests, unset the variable again and label the
   environment "benign-only, strict isolation OFF (namespace unavailable)". This is never an
   acceptable configuration for genuine malware; strict mode is not bypassed for that purpose.

### 2.5 Health monitoring

- Render health check on `/health`; enable workspace notifications for failed deploys and
  health-check failures.
- After each deploy: `curl https://…staging.onrender.com/health` →
  `"auth_configured":true,"scanners_ready":3`.
- Render logs: one `scan request_id=… verdict=…` line per scan; warnings/errors for scanner
  failures; no filenames or contents.
- Render metrics: watch memory during the 10 MB tests; if it nears 512 MB, lower
  `SECURITY_ENGINE_WORKER_MEMORY_MB` or move to Standard (`1c-2g`, about $25/month).
- Kill switch: delete `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` (every scan refused) or suspend the
  service.

## 3. Vercel: staging Security Lab

### 3.1 Why a CLI-deployed project

| Option | Verdict |
|--------|---------|
| Preview of the live project | Rejected: changes the live project's Preview env and shares it; and the branch is disabled by `vercel.json` |
| Second Git-connected project on the hardening branch | Rejected: `vercel.json` blocks that branch for this project too; would also auto-deploy `main` pushes (old code) |
| **New project, no Git connection, `vercel deploy --prod` from a clean checkout of `90453e4`** | **Chosen**: isolated settings and secrets; nothing deploys it except an explicit CLI command |

### 3.2 Procedure (needs you to log in to the Vercel CLI yourself: `npx vercel login`)

```bash
# 1. Clean, exact source (outside the working copy; no local files can leak into the upload)
git worktree add ../fm-staging-src 90453e4
cd ../fm-staging-src/frontend

# 2. Create and link a NEW project. Answer "No" to linking an existing project, name it
#    filesmagic-security-lab-staging, and DECLINE any offer to connect the Git repository.
npx vercel@latest link --project filesmagic-security-lab-staging
#    Check: the live project filesmagic-security-lab must NOT be selected.

# 3. Environment variables, Production environment of the STAGING project only.
#    Secret values are typed/pasted at the prompt from your password manager; never on the
#    command line (shell history) or in files in the repository.
npx vercel@latest env add NEXT_PUBLIC_SECURITY_ENGINE_URL production   # https://filesmagic-security-engine-staging.onrender.com
npx vercel@latest env add LAB_ADMIN_PASSWORD_HASH production --sensitive
npx vercel@latest env add LAB_SESSION_SECRET production --sensitive
npx vercel@latest env add LAB_SCAN_TOKEN_PRIVATE_KEY production --sensitive

# 4. Deploy (remote build on Vercel; NEXT_PUBLIC_ value is inlined at build time)
npx vercel@latest deploy --prod

# 5. Clean up the local link
cd ../.. && git worktree remove ../fm-staging-src
```

Checks after deploying:

- Dashboard → staging project → Settings → Git: **not connected** (if it is, run
  `npx vercel git disconnect` in the linked directory).
- Live project `filesmagic-security-lab`: no new deployment, settings unchanged.
- Use only the stable alias `https://filesmagic-security-lab-staging.vercel.app` (the only origin
  the staging engine allows). Per-deployment `*.vercel.app` URLs will fail CORS by design.
- The browser bundle points only at the staging engine: in DevTools → Sources, search the JS
  for `onrender.com`; only `filesmagic-security-engine-staging.onrender.com` may appear. (The
  live engine would also refuse it: its CORS list and its multipart API do not match.)

## 4. Authentication configuration

Staging gets its **own** keys and password; nothing is shared with any other environment.

| Variable | Where | What |
|----------|-------|------|
| `LAB_ADMIN_PASSWORD_HASH` | Vercel staging (sensitive) | `scrypt$<salt>$<hash>` of a long random password (≥ 20 characters, from a password manager) |
| `LAB_SESSION_SECRET` | Vercel staging (sensitive) | 32 random bytes, base64url |
| `LAB_SCAN_TOKEN_PRIVATE_KEY` | Vercel staging (sensitive) | Ed25519 private key, PKCS#8 DER, base64 |
| `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` | Render staging | matching Ed25519 public key, SPKI DER, base64 (not secret, but must match) |
| `SECURITY_ENGINE_CORS_ORIGINS` | Render staging | `https://filesmagic-security-lab-staging.vercel.app` |
| `NEXT_PUBLIC_SECURITY_ENGINE_URL` | Vercel staging | `https://filesmagic-security-engine-staging.onrender.com` (public by design) |

### 4.1 Generation (you run this locally; outputs go straight into your password manager)

Run in a terminal outside the repository; nothing is written to disk. Copy each value into the
password manager, then into the dashboards; clear the terminal afterwards.

```bash
node -e "const c=require('crypto');const k=c.generateKeyPairSync('ed25519');
console.log('LAB_SCAN_TOKEN_PRIVATE_KEY='+k.privateKey.export({format:'der',type:'pkcs8'}).toString('base64'));
console.log('SECURITY_ENGINE_TOKEN_PUBLIC_KEY='+k.publicKey.export({format:'der',type:'spki'}).toString('base64'));
console.log('LAB_SESSION_SECRET='+c.randomBytes(32).toString('base64url'))"
# Password hash: the password is read from a hidden prompt, not the command line
node -e "const c=require('crypto'),r=require('readline').createInterface({input:process.stdin,output:process.stdout});
r.stdoutMuted=true;r._writeToOutput=()=>{};process.stdout.write('Password: ');r.question('',p=>{const s=c.randomBytes(16);
console.log('\nLAB_ADMIN_PASSWORD_HASH=scrypt$'+s.toString('base64')+'$'+c.scryptSync(p,s,32).toString('base64'));r.close()})"
```

### 4.2 Verifying the key pair without revealing the private key

Prints only fingerprints (SHA-256 of the public key); they must be identical. The private key is
read from a hidden prompt.

```bash
node -e "const c=require('crypto'),r=require('readline').createInterface({input:process.stdin,output:process.stdout});
r._writeToOutput=()=>{};process.stdout.write('Private key (hidden): ');r.question('',priv=>{process.stdout.write('\nPublic key: ');
r._writeToOutput=s=>process.stdout.write(s);r.question('',pub=>{const fp=d=>c.createHash('sha256').update(d).digest('hex').slice(0,16);
const derived=c.createPublicKey(c.createPrivateKey({key:Buffer.from(priv.trim(),'base64'),format:'der',type:'pkcs8'})).export({format:'der',type:'spki'});
console.log('derived from private:',fp(derived));console.log('public key value:   ',fp(Buffer.from(pub.trim(),'base64')));r.close()})})"
```

End-to-end confirmation happens in acceptance test A3 (a real login + scan); a token signed by
any other key is rejected (A5).

### 4.3 Handling rules

- Private key, session secret and password: only in the password manager and Vercel staging
  (sensitive variables). Never in the repository, chat, screenshots, logs or CI.
- Claude does not need to see any of these values; the plan works if you enter them yourself.
- Rotation: generate a new pair, update both sides, redeploy both; old tokens die within 120 s.

## 5. Cost

| Item | Monthly |
|------|---------|
| Render Hobby workspace | $0 |
| Render Free instance (approved) | $0 |
| Render Starter instance, only with separate approval | about $7 |
| Render Standard instance, only if memory requires | about $25 instead of Starter |
| Vercel Hobby, second project | $0 (Hobby terms: personal, non-commercial use) |
| Expected total | **$0/month** on Free |

Confirm the current Render price in the dashboard before choosing; third-party sources and
Render's per-minute rates match $7 / $25.

## 6. Benign acceptance tests (browser, from the VM)

Files: the benign DOCX/PDF fixtures and the 16 `/test-files` fixtures (generated by the Lab;
inert). `ENGINE` = `https://filesmagic-security-engine-staging.onrender.com`,
`LAB` = `https://filesmagic-security-lab-staging.vercel.app`.

| # | Test | Steps | Expected |
|---|------|-------|----------|
| A1 | Health | Open `ENGINE/health` | `auth_configured: true`, `scanners_ready: 3` |
| A2 | Login required | Open `LAB/evaluation`, try a scan | Login form; no record created |
| A3 | Admin login | Wrong password, then correct one | "Incorrect password"; then login succeeds; cookie is HttpOnly, Secure, SameSite=Strict (DevTools → Application) |
| A4 | Login throttling | 6 wrong passwords | 6th → "Too many failed attempts" (per function instance) |
| A5 | Unauthorized uploads | DevTools console on `LAB`: `fetch(ENGINE+'/scan',{method:'POST',body:'x'})` and with `Authorization:'Bearer abc.def'` | 401 both; Render log `scan rejected` without the payload |
| A6 | Benign DOCX | Scan on `/` and `/evaluation` (expected Benign) | SAFE, `complete: true`, duration shown, request ID shown, outcome "Correct / SAFE" |
| A7 | Benign PDF | Same | SAFE |
| A8 | Synthetic library | `LAB/test-files`: download all 16, scan each on `/evaluation` (dataset "synthetic-fixtures"; these are inert indicators, not malware) | 16/16 match the library's expected verdicts (as verified locally through the worker) |
| A9 | Isolation reporting | Read the result's Isolation line | Record actual values; expected `network_namespace=NO` |
| A10 | Strict mode | §2.4 steps 2-3 | `UNABLE_TO_SCAN`, "required isolation unavailable: network_namespace"; evidence exported |
| A11 | Worker timeout | Set `SECURITY_ENGINE_WORKER_TIMEOUT_SECONDS=1`, redeploy, scan the DOCX; then restore `30` | `UNABLE_TO_SCAN`, scanners `error_kind: worker` "timed out after 1s"; `/health` still OK; one `scan worker failure` log line |
| A12 | Malformed input | Scan fixture `16-corrupted-document.pdf` | `UNABLE_TO_SCAN`, pdf `error_kind: malformed_input`; WARNING log without filename |
| A13 | Token replay | Console snippet below, part 1 | First upload 200, second with the same token 401 "already been used" |
| A14 | Token bound to file | Snippet part 2 | 403 "does not match the scan token" |
| A15 | Token expiry | Snippet part 3 (waits 150 s) | 401 "expired or not valid" |
| A16 | Size limit | Scan an 11 MB zero-filled file | Blocked in the browser with the 10 MB message; recorded as inconclusive |
| A17 | Exports | On `/evaluation`: Export CSV and JSON; also scan a benign file renamed `=cmd.txt` first | Files contain only metadata (no file bytes); CSV cell for `=cmd.txt` starts with `'=`; columns include `request_id`, `outcome`, `isolation` |
| A18 | Storage | DevTools → Application | Only `fm-evaluation-records-v1` (plus the test-files key); no file contents; session cookie not readable from JS |
| A19 | Live system untouched | Open the live Lab and live engine `/health` | Unchanged (live engine still answers without `auth_configured`) |

Worker crash handling (a real segfault) cannot be triggered on staging without test-only code;
it is covered by CI (`test_native_crash_fails_closed`, passed on Linux).

Token test snippet (paste in DevTools console on `LAB` while logged in):

```js
const ENGINE = "https://filesmagic-security-engine-staging.onrender.com";
const hex = async (b) => [...new Uint8Array(await crypto.subtle.digest("SHA-256", b))].map(x => x.toString(16).padStart(2, "0")).join("");
const token = async (b) => (await (await fetch("/api/scan-token", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ sha256: await hex(b), size: b.byteLength }) })).json()).token;
const scan = (b, t) => fetch(ENGINE + "/scan", { method: "POST", body: b, headers: { Authorization: "Bearer " + t, "Content-Type": "application/octet-stream" } }).then(async r => [r.status, (await r.json()).detail ?? "ok"]);
const a = new TextEncoder().encode("benign staging test A"), b = new TextEncoder().encode("benign staging test B");
const t1 = await token(a); console.log("replay:", await scan(a, t1), await scan(a, t1));        // A13
console.log("binding:", await scan(b, await token(a)));                                          // A14
const t3 = await token(a); await new Promise(r => setTimeout(r, 150000)); console.log("expiry:", await scan(a, t3)); // A15
```

## 7. Deployment sequence (each numbered step needs approval)

1. You: generate keys and password hash (§4.1), store them, verify the pair (§4.2).
2. You (or Claude via your logged-in browser, if you prefer): create the Render Hobby workspace
   and connect GitHub to this repository only.
3. Create the Render staging service (§2.2) with the §2.3 variables, `REQUIRE_ISOLATION` unset;
   manual deploy of `90453e4`; check A1.
4. `npx vercel login` (you), then create and deploy the Vercel staging project (§3.2); check the
   Git connection is off and the live project is unchanged.
5. Run A1-A9, A11-A19; then the strict-mode test A10 and preserve its evidence.
6. Record all results (exports + Render log excerpts) in the readiness report.

## 8. Rollback and teardown

Staging shares nothing with the live systems, so rollback never touches them.

| Situation | Action |
|-----------|--------|
| Staging misbehaves | Suspend the Render staging service (Dashboard → Settings → Suspend) |
| Stop all scanning immediately | Delete `SECURITY_ENGINE_TOKEN_PUBLIC_KEY` on Render staging, or delete `LAB_SCAN_TOKEN_PRIVATE_KEY` on Vercel staging (token route returns 503) |
| Suspected key exposure | Remove both variables, generate a new pair, redeploy; tokens expire within 120 s |
| End of staging | Delete the Vercel staging project; delete the Render service and (optionally) the Research workspace; remove that workspace's GitHub app access |
| Live systems | Never part of the rollback: no step above touches `filesmagic-security-lab` or the Personal Projects workspace |

## 9. Risks

| Risk | Mitigation |
|------|------------|
| Linking the CLI to the **live** Vercel project by mistake | Use `--project filesmagic-security-lab-staging`; check the project name before deploying; verify live project deployments afterwards |
| Vercel CLI connects the Git repo | Decline the prompt; verify Settings → Git; `vercel git disconnect` |
| Secrets in shell history or files | Hidden prompts (§4.1-4.2); `vercel env add` prompts; no `.env` files in the repo |
| Staging URLs are public | App-level admin login on the Lab; engine requires signed tokens; benign files only |
| 512 MB memory pressure | `WORKER_MEMORY_MB=256`, one scan at a time, watch metrics, Standard if needed |
| Render/Vercel account compromise affects both live and staging | Separate Render workspace limits the network blast radius only; use strong account security (2FA) |
| Hobby limits (one project, two environments per Render Hobby workspace; Vercel Hobby non-commercial) | Staging needs one service; confirm terms fit academic use |

## 10. Genuine-malware blockers (unchanged by staging)

| Area | Status | Why |
|------|--------|-----|
| Network egress isolation | **BLOCKED** | No egress firewall on Render; the worker's network namespace is unavailable in Docker (CI) and expected unavailable on Render (A10 will confirm). Only a Python audit hook remains, which is not an OS boundary |
| Separation from production | PARTIAL | New workspace + region removes the private-network path; the same Render and GitHub accounts remain a shared administrative blast radius |
| Runtime containment | **BLOCKED** | Worker shares the API's user and container; no separate UID, seccomp profile or VM-level sandbox on Render; rlimits only |
| Render hosting authorization | **BLOCKED** | Render's Acceptable Use Policy prohibits transmitting malware; written permission required before any live sample is uploaded |
| Research sample handling | **BLOCKED** | Needs a written procedure: samples stay inside the isolated VM; verified SHA-256 and source per sample; password-protected archives; no third-party uploads; retention and destruction rules; supervisor (and NIU, if required) approval |

Genuine-malware testing is **not ready**. Real samples belong in the offline harness inside the
isolated VM with networking disabled until every row above is resolved.
