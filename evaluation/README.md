# FilesMagic Security Engine — Evaluation Methodology

This directory holds the evaluation design and the offline harness used to measure
the engine against independently labelled benign and malicious documents. The goal
is to answer one question with evidence:

> Can a lightweight, format-aware document scanner (YARA-X + Office + PDF structural
> analysis) provide useful detection within a 512 MiB / 0.15 CPU cloud budget, and
> at what false-positive cost?

It is not an antivirus certification. Results apply to the dataset described below
and to the engine commit recorded in each run.

**No samples live in this repository.** Malicious samples exist only inside the
isolated evaluation VM, outside the repository checkout, and never leave it.

## 1. What is evaluated

The system under test is the engine's `/scan` code path, run **in-process** inside
the evaluation VM (`evaluate.py` uses FastAPI's TestClient: same scanners, decision
engine and 10 MB upload limit as production, no network). The public Render service
is never used for malicious samples; it is for benign/synthetic validation only.

Per sample the harness records: verdict (`SAFE`, `SUSPICIOUS`, `MALICIOUS`,
`UNABLE_TO_SCAN`), or `REJECTED` (HTTP 413, over 10 MB) or `ERROR` (any other failure);
the rule IDs, scanners and maximum severity of the findings; the API message; and
the in-process scan duration.

## 2. Ground truth

The engine's verdict never defines ground truth. Every sample carries a label from
an independent source and a written `ground_truth_basis` explaining why it is trusted.

| Label | Meaning | Scored? |
|-------|---------|---------|
| `BENIGN` | Legitimate file from a trustworthy publisher, **and** no detection when its hash is checked against independent multi-engine intelligence at acquisition time | Yes (negative class) |
| `MALICIOUS` | Independently confirmed malicious: listed in a curated malware repository with a family/signature attribution **and** corroborated by independent vendor detections (target: ≥ 5 engines) or a published analysis | Yes (positive class) |
| `SECURITY_TEST` | Standardised harmless test artifact (e.g. EICAR) | No — reported separately |
| `EXCLUDED` | Label cannot be established (conflicting evidence, too few detections, unknown origin, broken file) | No — counted, not scanned |

"Suspicious" is **not** a ground-truth class. A benign document with macros or forms
stays `BENIGN`; the engine flagging it is exactly the false-positive cost we want to
measure. A file whose maliciousness is unclear is `EXCLUDED`, not guessed.

Known label risks: GovDocs1 states that it contains some malware as found on
government servers, so "benign" corpora must be hash-checked; vendor detection counts
can be wrong or change over time (record the lookup date); and labels derived from
AV detections favour samples AV already knows (see §8).

## 3. Mapping verdicts to outcomes

The engine has four verdicts, so there is no single binary matrix. The harness
always reports the full **ground truth × outcome** table (mapping-free), plus three
binary views. Ground truth `MALICIOUS` is positive, `BENIGN` negative.

| View | Detection (predicted positive) | Pass (predicted negative) | Not in matrix | Question it answers |
|------|-------------------------------|---------------------------|---------------|---------------------|
| **block** (primary) | `SUSPICIOUS`, `MALICIOUS` | `SAFE` | `UNABLE_TO_SCAN`, `REJECTED`, `ERROR` → coverage | Would the gate stop the file automatically, among files it could analyse? |
| **block_fail_closed** | `SUSPICIOUS`, `MALICIOUS`, `UNABLE_TO_SCAN`, `REJECTED` | `SAFE` | `ERROR` | What does a user experience? (Production never converts unscanned files.) |
| **conviction** | `MALICIOUS` | `SAFE`, `SUSPICIOUS` | `UNABLE_TO_SCAN`, `REJECTED`, `ERROR` | How often is a hard "malicious" call right, and how much is caught with high confidence? |

Effects: *block* gives the highest recall and the highest FPR (every flagged benign
form or macro is an FP). *block_fail_closed* raises both further by counting coverage
failures as blocks — the honest operational FP burden. *conviction* has the lowest
FPR and lowest recall; malicious files rated only `SUSPICIOUS` become FNs here, which
shows how much detection depends on the review-required tier. Reporting all three
keeps the meaning of `SUSPICIOUS` visible instead of hiding it in a binary label.

Definitions (per view): **TP** = malicious and predicted positive; **FN** = malicious
and predicted negative; **FP** = benign and predicted positive; **TN** = benign and
predicted negative.

## 4. Metrics

| Metric | Formula | Notes |
|--------|---------|-------|
| Recall / detection rate (TPR) | TP / (TP + FN) | Main detection measure |
| Specificity (TNR) | TN / (TN + FP) | |
| False-positive rate | FP / (FP + TN) | Main cost measure for a conversion gate |
| False-negative rate | FN / (FN + TP) | |
| Precision | TP / (TP + FP) | **Depends on the benign:malicious ratio of the dataset**; real upload traffic is overwhelmingly benign (base-rate fallacy), so precision on a balanced set overstates field precision |
| F1 | 2·P·R / (P + R) | Inherits precision's base-rate dependence |
| Accuracy | (TP + TN) / all scored | Reported but not used for conclusions: misleading under class imbalance |
| Balanced accuracy | (TPR + TNR) / 2 | Prevalence-independent summary |
| Coverage failure rate | (UNABLE_TO_SCAN + REJECTED + ERROR) / scanned, per class | How often the engine cannot decide |
| Latency | mean, median, p95, max per file type | In-process, VM hardware; not network time |
| Peak memory | process peak RSS (Linux) | Render production memory from Phase 4 metrics |

Every proportion is reported with a **95% Wilson score interval** (NIST/SEMATECH
e-Handbook §7.2.4.1), which stays valid near 0 and 1 where the normal approximation
fails. Undefined metrics (zero denominator) are reported as "–", never as 0.
Metrics are reported overall and **per file type**; small per-type cells are
reported with their counts and wide intervals rather than over-interpreted.
Rule hit counts on benign files drive the false-positive analysis.

## 5. Dataset design

Scope is documents FilesMagic converts: PDF, OOXML (DOCX/XLSX/PPTX and macro-enabled
variants) and legacy OLE (DOC/XLS/PPT). Executables and archives are out of scope
and are not used to inflate counts. All samples must be ≤ 10 MB (larger files are
`REJECTED` by design and would only measure the size limit).

Sample sizes, from the Wilson interval widths:

| Per class | 95% CI width at 90% recall | FPR upper bound if 0 FPs | Verdict |
|-----------|---------------------------|--------------------------|---------|
| 50 | ±8.5 pts | 7.1% | Too wide for claims |
| **100 (minimum viable)** | ±6 pts | 3.7% | Supports coarse claims |
| 150 | ±5 pts | 2.5% | |
| **300 (preferred)** | ±3.4 pts | 1.3% | Supports per-format statements |

Proposed composition (preferred target, ~600 scored samples):

| Stratum | Benign | Malicious |
|---------|-------:|----------:|
| PDF — plain | 80 | — |
| PDF — active (forms/AcroForm, JavaScript, attachments, XFA) | 40 | — |
| PDF — malicious (JavaScript, launch, embedded payloads, exploits) | — | 120 |
| OOXML — plain DOCX/XLSX/PPTX | 60 | — |
| OOXML — legitimate macro-enabled / templates / external links | 30 | — |
| OOXML — malicious (macros, remote templates, external OLE, DDE) | — | 100 |
| Legacy OLE — DOC/XLS/PPT (incl. some with legitimate macros) | 60 | — |
| Legacy OLE — malicious (VBA, XLM, embedded objects, Equation Editor) | — | 70 |
| Other text/CSV (applicability check) | 30 | — |
| **Total** | **300** | **290** |

Minimum viable: 100 benign + 100 malicious with the same proportions. The
"benign but active" strata are deliberately over-represented relative to real
traffic: they are where false positives occur and where the engine's design choices
(severity of macros, forms, JavaScript) are actually tested.

## 6. Sources (reviewed, nothing downloaded in Phase 5A)

| Source | Contents | Ground truth | Access / terms | Use |
|--------|----------|--------------|----------------|-----|
| [GovDocs1, Digital Corpora](https://digitalcorpora.org/corpora/file-corpora/files/) | ~1M real files from .gov servers (PDF, DOC, XLS, PPT, …), 1,000-file "threads" | Publisher-origin; **corpus states some malware is included** → hash-check every file | Free for research, redistributable; cite Garfinkel et al., DFRWS 2009 | **Primary benign source** (legacy Office + PDF) |
| Official government/agency forms and templates (e.g. fillable federal forms, Microsoft Office templates) | Benign PDFs with AcroForm/JavaScript/XFA; Office templates | Publisher-origin | Public; record URL and date | Benign **active-content** strata |
| Locally authored documents (Word/Excel/LibreOffice) incl. a harmless macro | Benign OOXML/OLE | Created by us | Ours | Fill strata; flagged `source=authored` and reported separately (authoring-tool bias) |
| [MalwareBazaar, abuse.ch](https://bazaar.abuse.ch/api/) | Vetted malware only; queryable by file type (pdf, doc, docm, xls, xlsm, …), family, tags; `first_seen` dates | Submitter + family signature + vendor/ClamAV intelligence in metadata | **Free Auth-Key required**; fair use; 2,000 downloads/IP/day; AES ZIP, password `infected` | **Primary malicious source** — supports date-based splits |
| [Contagio malicious documents](https://contagiodump.blogspot.com/2010/08/malicious-documents-archive-for.html) | ~11k malicious PDF/Office files 2008–2011, CVE-labelled | Analyst-labelled | Original links dead; waiver of liability | Historical only; not planned |
| [VirusShare](https://virusshare.com/about) | Large live-malware repository, mostly executables | Hash-based | **Invitation only; automated access forbidden** | Not recommended |
| VirusTotal (multi-engine lookups; academic programme) | Detection reports for hashes | Multi-vendor consensus | API key; academic terms could not be verified (page not readable) | Hash lookups for label corroboration only |
| [CIC-Evasive-PDFMal2022](https://www.unb.ca/cic/datasets/pdfmal-2022.html) | 37 extracted features for 10,025 PDFs | Contagio/VirusTotal + clustering | Redistributable with citation | **Not usable directly** (no PDF files); related work |
| theZoo and similar GitHub malware dumps | Live malware, mixed provenance | Weak | Varies | Not recommended |
| [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) | 68-byte DOS `.com` test string, "not a virus" | Standardised | Free, at own risk | Optional `SECURITY_TEST` sanity check of the ClamAV baseline only; **no document variant exists**, out of scope for this engine |
| [AMTSO Security Features Check](https://www.amtso.org/security-features-check/) | Harmless checks for downloads, PUA, phishing, cloud lookup | Standardised | Free, terms apply | No document-format artifacts; not used |

Redistribution: sample files are never published. The final report publishes only
hashes, labels, sources and aggregate results, which all sources above permit.

## 7. Dataset hygiene

- SHA-256 of every file is recorded in the manifest and **re-verified by the harness**
  before scanning (mismatch = run aborted). Exact duplicates are detected by hash; only
  the first occurrence is scanned and the rest are reported as skipped.
- Near-duplicates (same family, template or builder) are **not** removed automatically
  (fuzzy hashing adds tooling with unclear thresholds for a dataset this size). Instead:
  cap samples per malware family (target ≤ 10%, i.e. ~10 per 100) using MalwareBazaar's
  `signature` field, and report per-family results so a single family cannot dominate.
- Benign, malicious, test and excluded samples live in separate folders and are labelled
  in the manifest; synthetic/authored files are tagged so they can be reported apart from
  real-world files.
- Samples are stored outside the repository. The harness refuses a samples root inside
  the repository, never sends sample bytes anywhere, and writes only metadata.
- Git ignores `samples/`, `results/` and common archive/executable extensions as a
  second line of defence. Never commit, push, upload to Vercel/Render or copy to the host
  any malicious sample.

## 8. Avoiding biased results

Following Arp et al. (2022) and Pendlebury et al. (2019):

- **Development vs holdout.** Split the dataset before any analysis. Rules and severity
  thresholds may only be tuned on `dev`. The `holdout` split is scanned once, at the end,
  with the final engine commit, and reported as the headline result. Results on `dev`
  after tuning are labelled as optimistic.
- **Time-aware split.** Assign malicious samples to `dev`/`holdout` by `first_seen` date
  (older → dev, newer → holdout) so tuning cannot use "future" malware.
- **No snooping.** Do not read holdout findings while changing rules. Record every rule
  change made after looking at `dev` results.
- **Sampling bias.** Real uploads are mostly benign, plain documents; the dataset is not.
  Report rates per stratum and do not extrapolate precision to production.
- **Label bias.** Malicious labels from AV-derived sources favour already-known samples.

## 9. ClamAV reference baseline (VM only)

Recommended, as an optional comparison on the same files, **never** in production:

- Run `clamscan` on each sample inside the VM with a recorded signature-database
  version, then disconnect the network; map "FOUND" → positive, "OK" → negative,
  errors → coverage failure.
- Compare: block-view recall and FPR, coverage, per-file latency and memory (the
  Phase 3A research found ~1.2 GiB to load signatures; the VM needs ≥ 4 GB RAM).
- Limitations: different goals (broad signature AV vs document-structure gate);
  ClamAV includes hash signatures for known samples, and MalwareBazaar metadata itself
  lists ClamAV detections, so **ClamAV recall on MalwareBazaar samples is inflated by
  construction**; results depend on signature freshness. Present it as context, not as a
  contest.

## 10. VM safety procedure

The Ubuntu 24.04 VM (VirtualBox, snapshot "Clean Ubuntu 24.04 - Pre Security Engine")
is the only place malicious samples ever exist.

1. **Before anything malicious arrives** (VM powered off): Shared Clipboard **Disabled**,
   Drag'n'Drop **Disabled**, no Shared Folders, no USB pass-through. Verify in the VM
   settings and record screenshots. Take snapshot **"Eval baseline – tools installed"**
   after installing the engine, dependencies and (optionally) ClamAV.
2. **Network:** NAT on only for installing tools/signatures and for downloading samples;
   **Not attached** while samples are extracted and evaluated, and while results are prepared.
3. **Storage:** samples under `~/fm-eval/samples/{benign,malicious,test,excluded}/` with
   `chmod -R a-x`; the repository checkout lives separately at `~/filesmagic-security-engine`.
   Keep MalwareBazaar ZIPs encrypted until the moment of extraction; extract with a
   command-line tool only.
4. **Data, not documents:** never open samples in LibreOffice, a PDF viewer, a browser or
   the file manager; do not double-click. Disable GNOME Tracker indexing / thumbnails for
   `~/fm-eval` (or the whole session) so nothing previews samples automatically. The only
   programs that read samples are the harness, `sha256sum` and `clamscan`.
5. **Run:** `python -m evaluation.evaluate --manifest ~/fm-eval/manifest.csv
   --samples-root ~/fm-eval/samples --split dev --out evaluation/results/dev-001`.
6. **Export (metadata only):** `per_sample.csv`, `summary.json`, `summary.md` and the
   manifest contain hashes, labels and rule IDs — never sample bytes. Review them, then
   transfer by reconnecting the network and committing them from the VM (or pasting the
   reviewed text) — **never** via shared folders, clipboard of files or USB, and never
   transfer sample files to the host.
7. **Revert:** after each evaluation session, power off and restore "Eval baseline" (or
   the clean snapshot) so no extracted sample persists between sessions.
8. **Never** submit malicious samples to the public Render service or the Vercel
   Security Lab.

## 11. Using the harness

```bash
pip install -r requirements-dev.txt          # engine + TestClient
cp evaluation/manifest_template.csv ~/fm-eval/manifest.csv   # then fill it in
python -m evaluation.evaluate --manifest ~/fm-eval/manifest.csv \
    --samples-root ~/fm-eval/samples --split dev --out evaluation/results/dev-001
```

Manifest columns: `sample_id, sha256, path` (relative to the samples root),
`file_type, ground_truth, ground_truth_basis, source, source_ref, acquired_date,
split` (`dev`/`holdout`), `active_content, encrypted` (`yes`/`no`/`unknown`), `tags,
notes`. Outputs go to `evaluation/results/<run>/` (git-ignored); copy reviewed final
summaries into `evaluation/reports/` for the capstone report.

Each `summary.json` records the engine commit (and whether the tree was dirty), the
manifest's SHA-256, Python/platform and scanner package versions, so every number can
be traced to an exact engine and dataset.

## 12. Evidence to keep for the report

Manifest (hashes, labels, sources, split), per-run `summary.json`/`summary.md` and
`per_sample.csv`, engine commit per run, the list of rule changes made on `dev`,
ClamAV database version (if used), VM settings screenshots, and Phase 4 Render
resource measurements.

## References

- D. Arp et al., "Dos and Don'ts of Machine Learning in Computer Security", USENIX Security 2022.
- F. Pendlebury et al., "TESSERACT: Eliminating Experimental Bias in Malware Classification across Space and Time", USENIX Security 2019.
- NIST/SEMATECH e-Handbook of Statistical Methods, §7.2.4.1 (confidence intervals for proportions).
- AMTSO Testing Protocol Standard v1.3 (2019) — transparency of test plans and sample handling.
- S. Garfinkel et al., "Bringing Science to Digital Forensics with Standardized Forensic Corpora", DFRWS 2009 (GovDocs1).
- abuse.ch MalwareBazaar API documentation; EICAR anti-malware test file page.
