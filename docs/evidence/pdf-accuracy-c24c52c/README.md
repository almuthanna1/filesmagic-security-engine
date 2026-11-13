# PDF attachment accuracy: before/after evidence (`2d586f6` -> `c24c52c`)

Plan and predictions, committed first: [`docs/pdf-accuracy-preregistration.md`](../../pdf-accuracy-preregistration.md)
(`a8be874`). Change: `c24c52c`. Harness: `evaluation/pdf_accuracy.py`.

    python -m evaluation.pdf_accuracy --before <checkout of 2d586f6> --local <dev map> --local <held-out map> \
        --trials 3 --out <dir>

Files: `summary.md` / `summary.json` (rule IDs, counts and timings only). The full per-sample
findings (`results.json`) stay local: they quote text from private documents. Windows 11, Python
3.14.3, pypdf 6.19.0, yara-x 1.21.0; each tree scanned by its own worker subprocess; 3 trials per
scan, all deterministic. The header line says "uncommitted changes": git reported a stale stat entry
for `evaluation/pdf_accuracy.json` (line-ending rewrite; `git diff` was empty, index and working copy
both LF), so the code that ran is exactly `c24c52c`.

## Predictions

| | Prediction | Result |
|---|---|---|
| P1 | Reference engine identical on every sample | **held** (0 changes in 130 samples) |
| P2 | Unified: only SUSPICIOUS -> SAFE on PDFs whose only non-INFO finding was `PDF_Embedded_File`, with `ENGINE_PDF_NO_ATTACHMENTS` | **held**: D2, S01, S02, S03; plus S17 losing its YARA-X LOW while staying MALICIOUS (predicted in P4) |
| P3 | D1 SUSPICIOUS, D2 -> SAFE, D3 SAFE | **held** |
| P4 | Synthetic required outcomes; dangerous MALICIOUS before and after | **held**: 17/17 |
| P5 | `cases()` and `field_cases()` unchanged | **held** (22/22 identical) |
| P6 | No HIGH/CRITICAL lost; no new MALICIOUS on benign | **held** |
| P7 | Unified PDF scan latency within 10 ms | **held**: pdf-chains time per PDF, paired, median -0.5 ms (range -7.3 to +0.4) |

## What the held-out set shows, and does not

None of the 59 held-out documents carries the structure the change addresses: all 55 private
ones and the Census workbook are SAFE in both engines before and after; the three IRS forms stay
SUSPICIOUS (automatic form JavaScript, `ENGINE_PDF_AUTO_CHAIN_SCRIPT` MEDIUM; their attachment is
real and their older revisions make the attachment list incomplete, so the attachment findings
stand). So the held-out run confirms **no regression** (0 changes; unified false positives 0/59,
95% CI 0-6.1%) but provides **no independent evidence of the improvement**, which rests on D2 and
the synthetic set. The reference engine's 3 held-out false positives (IRS forms, MALICIOUS through
`PDF_AUTO_JAVASCRIPT_WITH_PAYLOAD`) are unchanged and were already corrected by the unified engine.

## Remaining warnings on benign documents (unified, after)

| Document | Verdict | Why | Assessment |
|---|---|---|---|
| D1 | SUSPICIOUS | a genuine C2PA manifest, not verifiable (`ENGINE_PDF_ATTACHMENTS_UNVERIFIED`, LOW) | justified: the manifest embeds an SVG, and no C2PA verifier exists |
| IRS f1040, fw4, fw9 | SUSPICIOUS | automatic JavaScript (MEDIUM) | justified by policy: scripts run on open |
| `docx-05-word-custom-template` | SUSPICIOUS | template on a drive path loaded on open (LOW) | deliberate (C10) |

## Latency

Wall time per scan is about 600 ms, of which the scanners take about 10 ms (median): the rest is
the fresh worker process. Comparing runs needs pairing: the unchanged reference engine also became
25.5 ms faster from the first run to the second (order effect), the unified engine 26.7 ms. The
slowest scanners are content-proportional on large PDFs (7-8 MB job aids): `custom` up to 255 ms,
`pdf-chains` up to 106 ms. Scanners that find their format not applicable take under 1 ms
(`vba-chains`) and under 7.3 ms (`word-fields`, p95 2.6 ms), so the 86-92 ms "not applicable" times
seen on the staging host are not the code's own cost here; they remain to be measured there.
