# Real-world benign document validation

29 legitimate, non-sensitive documents (8 PDF, 7 DOCX, 7 XLSX, 7 PPTX) made by real producers —
Microsoft Word, Excel and PowerPoint 16, LibreOffice and Microsoft Edge — from neutral text
(a community-garden plan). They exercise ordinary features that detectors may confuse with attack
structure: links, tables of contents, comments, tracked changes, embedded and linked objects,
custom templates, external workbook links, pivot tables, charts, animations, PDF/A, tagged PDF,
and LibreOffice hybrid PDF.

## Ground truth

| Class | Meaning | In this corpus |
|---|---|---|
| **Known-benign (authored)** | Made here by `build.ps1` from neutral text with a real producer; no macros, personal information removed, contents checked. | all 29 files |
| Benign by provenance | Published by a trusted organisation and downloaded from its official site; very likely benign, not verified byte by byte. | none yet (needs approval to download) |
| Unknown | Anything else. A scan result never moves a file into a benign class. | none, by design |

A SAFE verdict means *no known indicators were found*, not that a file is harmless. Here a SAFE
verdict on a known-benign file is a correct negative, and SUSPICIOUS or MALICIOUS is a false positive.
For a file of unknown origin, SAFE would be no evidence of harmlessness at all.

Never add genuine malware, EICAR test files, or private or customer documents to this corpus.

## Files

- `build.ps1`: how the files were made (Windows, Office 16, LibreOffice, Edge). Office embeds
  timestamps, so a rebuild gives new bytes: the committed `files/` are the reference copy.
- `manifest.json`: SHA-256, size, producer, ground truth, and the structural features found in each
  file's bytes (`python -m evaluation.benign_corpus.manifest`).
- `local.py`: internal baseline. Both engines run in the real worker locally, with no token.

## Manual checklist (Security Lab, staging)

Prerequisites: staging Lab https://filesmagic-security-lab-staging.vercel.app, engine
https://filesmagic-security-engine-staging.onrender.com, a fresh browser profile (History is per browser).

1. Check `manifest.json` against the files: `sha256sum files/*` must match.
2. Open the Lab and wait for **"This API accepts both engines (commit …)"**. A sleeping engine
   shows a retry message first. Record the commit.
3. Budget: the token limit is 12 per 15 minutes and a comparison uses 2, so run at most
   **6 comparisons per 15 minutes**. Do not raise the limit.
4. For each file in `files/`, in manifest order:
   1. Select **Compare both**, choose the file and click **Scan with both engines**.
   2. Check both results show the file's SHA-256 from the manifest and the expected commit.
   3. Check **Isolation** shows "Strict isolation required" and `isolation_missing: []` for both.
      If not, **stop testing** and report it.
   4. Record each engine's verdict, its non-INFO findings, "All applicable scanners completed"
      or "Incomplete", the whole-scan time and the detection time.
   5. Classify the outcome: SAFE → correct negative. SUSPICIOUS or MALICIOUS → false positive:
      note the rule and which document feature caused it. UNABLE_TO_SCAN → incomplete scan: note the
      scanner and its error.
5. On the History page, use **Export JSON** and **Export CSV** and keep both with the run.
6. Compare against the internal baseline (`python -m evaluation.benign_corpus.local --out …`):
   the same verdicts are expected, since both run the same engine code. Any difference is a finding.
