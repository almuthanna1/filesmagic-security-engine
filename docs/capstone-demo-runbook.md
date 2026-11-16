# Capstone demonstration runbook (5-10 minutes)

**Audience:** Dr. Nur Imtiazul Haque. **Presenter:** Almuthanna Shihab.
**System:** staging only. Lab <https://filesmagic-security-lab-staging.vercel.app> (Vercel
`dpl_4RLCd1apcJmGAsCY4Pwq6Bqr7WQ8`, commit `279ad39`) and engine
<https://filesmagic-security-engine-staging.onrender.com> (Render `dep-dbfplih42hec738cakpg`,
commit `0a91480`). Background: [capstone-evidence-package.md](capstone-evidence-package.md).

**Ground rules**

- Use only the Lab's built-in synthetic fixtures. Never use genuine malware.
- Never show the Render or Vercel environment-variable pages, `.env` files, the admin password,
  scan tokens or the browser's network panel (it shows bearer tokens).
- Do not open active-content fixtures in Office or PDF viewers. Download them, then upload them
  straight to the Lab.

## Preparation (10-15 minutes before)

1. **Wake the engine.** Render Free sleeps after 15 minutes idle, so open
   `https://filesmagic-security-engine-staging.onrender.com/health`. Expect `"status":"ok"`,
   `"scanners_ready":3` and `"auth_configured":true`. The first request after sleep can take
   about a minute. Reload `/health` just before starting, then keep using the service so it
   stays warm.
2. **Log in.** Sign in to the staging Lab in a private window, typing the password from your
   password manager while not screen-sharing.
3. **Download the three fixtures** from **Test files** into a demo folder:
   `05-benign-document.docx`, `04-benign-document.pdf` and `13-pdf-launch-indicator.pdf`.
4. **Open in tabs:** the Lab's **Malware evaluation** page, the
   [architecture diagram](capstone-evidence-package.md#3-security-architecture), the latest
   [CI run](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/40381320558),
   and the fallback evidence (Section F below).
5. **Optional:** clear old local records (**Clear records**) so the table shows only today's
   scans. Export any records you want to keep first.

## Option A: core demonstration (about 5 minutes)

Use this when time is short. Every step is taken from the full version (Option B); the timings
assume a warm engine.

| # | Time | Show | Say (key points) |
|---|---|---|---|
| A1 | 0:00-1:00 | Architecture diagram | A document gate for a converter: YARA-X plus Office and PDF analysis. The Lab signs a short-lived token bound to the file's hash; the browser uploads directly to the engine; each scan runs in a fresh worker that fails closed. This is a separate research staging deployment, not part of the customer-facing FilesMagic pipeline. |
| A2 | 1:00-2:00 | **Malware evaluation**: scan `05-benign-document.docx` (label Benign, source "synthetic-control (demo)") | Expect `SAFE` in about 6-7 s, with the applicable scanners complete. SAFE means no known indicator, not "proven harmless". |
| A3 | 2:00-3:00 | **Scanner** page (no expected label): scan `13-pdf-launch-indicator.pdf` | Expect `MALICIOUS` with `PDF_Launch_Action` and `PDF_LAUNCH_ACTION`. This is an inert synthetic indicator test: a `/Launch` action with no target, built to exercise these rules. The verdict shows the rule fires. It is not malware and not ground truth, and says nothing about detection accuracy. |
| A4 | 3:00-4:15 | Isolation report of that result | Strict mode is on and `isolation_missing` is empty. `net_loopback_only=false` with `net_fallback_tunnel_inert=true` is the `tunl0` finding, accepted only after field-by-field checks, with capabilities dropped afterwards. Linux CI exercises this against a real kernel; on Render these are the worker's own kernel read-backs. |
| A5 | 4:15-5:00 | Evidence package §16-§18 | Not a sandbox (shared container and kernel; the API has internet access). No accuracy measured yet. Next: your approval of the procedure, NIU's determination, the offline VM, a labelled dataset. |

## Option B: full demonstration (about 10 minutes)

| # | Time | Show | Say (key points) |
|---|---|---|---|
| 1 | 0:00-1:00 | Title slide or the evidence package abstract | FilesMagic converts user documents, and hostile documents are a real risk for a converter. I built a security gate that scans uploads with YARA-X plus Office and PDF structural analysis, in an isolated worker that fails closed. It runs as a separate research staging deployment and is not integrated into the customer-facing pipeline. Today: what it does, how I validated it, and what is not yet proven. |
| 2 | 1:00-2:30 | Architecture diagram | Walk the numbered arrows. Login gives a session. The Lab signs a 120-second, single-use token bound to the file's hash and size. The browser uploads directly to Render; the file never passes through Vercel. The engine verifies the token before reading the body. A fresh worker enters its own user and network namespace, verifies there's no usable route, drops all capabilities, then parses. Point at the limits box: the worker shares the container and kernel, and the API itself still has internet access. |
| 3 | 2:30-3:30 | Malware evaluation page; upload `05-benign-document.docx`, source "synthetic-control (demo)", label Benign; **Scan and record** | Expect `SAFE` in about 6-7 s: YARA-X and Office completed, PDF not applicable. SAFE means no known indicator, not "proven harmless". Point at the request ID: that is how a result is matched to the server log, which holds no filenames or contents. |
| 4 | 3:30-4:15 | Upload `04-benign-document.pdf` (Benign, source "synthetic-control (demo)") | Expect `SAFE`: YARA-X and PDF completed. Same isolation report. Both benign files are self-generated controls, not independently sourced benign samples. |
| 5 | 4:15-5:15 | Switch to the **Scanner** page, which asks for no expected label, and scan `13-pdf-launch-indicator.pdf` | Expect `MALICIOUS` with `PDF_Launch_Action` (YARA-X) and `PDF_LAUNCH_ACTION` (structural). Say clearly that this is an **inert synthetic indicator test**: a `/Launch` action with no target, built to exercise these rules. "MALICIOUS" is the engine's verdict for that indicator. It is not independent malware ground truth or a real sample, and not evidence of detection accuracy. (It is scanned outside the evaluation page so that it isn't recorded under "Independently verified classification".) |
| 6 | 5:15-6:45 | The **Isolation** report of the Launch-fixture result | `isolation_required: true` means strict mode, so the worker refuses to scan unless every required control holds. `isolation_missing: []` means none is missing. `net_loopback_only: false` with `net_fallback_tunnel_inert: true` is the `tunl0` story: the first strict deployment refused all scans because Render's kernel adds an inert IP-in-IP device. I diagnosed it with log-only diagnostics, accepted only that exact device after field-by-field verification, and added capability dropping so the worker can't reconfigure the network afterwards. Linux CI proves the kernel behaviour, including with the real `tunl0`; on Render these values are reported by the worker itself. |
| 7 | 6:45-7:45 | **Recorded results**; **Export CSV** (open it briefly) | Records keep metadata only: hashes, verdicts, rule IDs, isolation and request IDs, never file contents. Mention the evidence: 368 Linux tests plus a 27-test rerun with `tunl0` in the latest CI run; 19/19 staging acceptance checks and 16/16 fixtures in Phase C4. These are functional results, not accuracy measurements. |
| 8 | 7:45-8:45 | Evidence package §16-§17 | Limitations: not a sandbox (shared user, container and kernel); API egress; a self-reported isolation status on Render; rule-based detection only. Validity: fixture expectations come from my own rules, and there is no labelled real-world data yet. |
| 9 | 8:45-10:00 | Evidence package §18-§19 | Next: your approval of the handling procedure, NIU's determination, the source terms, and the offline VM. Then a frozen, independently labelled dataset with time-aware splits and metrics with Wilson intervals. Hosted genuine-malware work stays blocked without Render's written authorization and stronger containment. Ask for a decision on these approvals. |

**If a result differs from what's expected:** read it out as observed. `UNABLE_TO_SCAN` with a
non-empty `isolation_missing` means strict mode worked and refused the scan. Note the request
ID, continue with the fallback (Section F), and investigate afterwards. Don't change settings
during the meeting.

## F. Fallback if Render is asleep, slow or unavailable

1. Say so plainly: the Free instance sleeps or is unavailable, so you'll show recorded evidence
   from the same deployment.
2. Show the recorded hosted results (evidence package §13), which use the same commit
   `0a91480` and deployment `dep-dbfplih42hec738cakpg`:
   - **C7E:** DOCX `SAFE` (`c0d5fa59d3194922`, 7,111 ms), PDF `SAFE` (`e6bbdbfdf4594524`,
     6,342 ms), inert synthetic Launch-indicator PDF `MALICIOUS` (`5edb0d4ba37d4b3c`,
     6,433 ms);
   - **C7D:** `d725d991ca8944c1`, `9da181d003954729`, `406c1cb8b72e4797`.
3. Show the latest
   [CI run 40381320558](https://github.com/almuthanna1/filesmagic-security-engine/actions/runs/40381320558)
   with all three jobs green, then open the backend job's log for 368 passed and 27 passed.
4. If you still have them, open the earlier Lab records or exported CSV/JSON from C7E (local
   files). The Lab's records live in browser storage on the machine that made them.
5. Walk through the `tunl0` table in evidence package §10 instead of the live isolation report.

If only the Lab is down but Render is up, don't improvise a scan through other tools. Use the
fallback.
