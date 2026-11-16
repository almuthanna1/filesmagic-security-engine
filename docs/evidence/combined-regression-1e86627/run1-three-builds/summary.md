# Combined-build accuracy regression

Windows-11-10.0.26300-SP0, 3 trials per scan. Every sample is benign or an inert synthetic construction (no malware).

- **candidate**: `ca8ca9a7bc1d` (dirty: True), pypdf 7.0.1
- **90718ff**: `90718ffc6a7d` (dirty: False), pypdf 7.0.1
- **840a300**: `840a300c1edf` (dirty: False), pypdf 6.19.0

| Measure | candidate | 90718ff | 840a300 |
|---|---|---|---|
| Samples | 252 | 252 | 252 |
| Unified SAFE | 153 | 158 | 153 |
| Unified UNABLE_TO_SCAN | 5 | 0 | 5 |
| Unified SUSPICIOUS | 85 | 85 | 85 |
| Unified MALICIOUS | 9 | 9 | 9 |
| detection TP | 55 | 55 | 55 |
| detection FP | 9 | 9 | 9 |
| detection TN | 134 | 134 | 134 |
| detection FN | 0 | 0 | 0 |
| detection precision | 0.8594 | 0.8594 | 0.8594 |
| detection recall | 1.0 | 1.0 | 1.0 |
| detection f1 | 0.9244 | 0.9244 | 0.9244 |
| detection false_positive_rate | 0.0629 | 0.0629 | 0.0629 |
| gate TP | 55 | 55 | 55 |
| gate FP | 14 | 9 | 14 |
| gate TN | 129 | 134 | 129 |
| gate FN | 0 | 0 | 0 |
| gate precision | 0.7971 | 0.8594 | 0.7971 |
| gate recall | 1.0 | 1.0 | 1.0 |
| gate f1 | 0.8871 | 0.9244 | 0.8871 |
| gate false_positive_rate | 0.0979 | 0.0629 | 0.0979 |
| Scanner failures (sample, scanner) | 1 | 1 | 1 |
| Worker errors | 0 | 0 | 0 |
| Incomplete coverage (samples) | 14 | 0 | 14 |
| Case mismatches vs frozen | 0 | 0 | 0 |
| Not deterministic | 0 | 0 | 0 |
| Unified latency median (ms) | 546.8 | 560.8 | 544.5 |
| Unified latency p95 (ms) | 820.1 | 800.1 | 724.0 |
| Unified latency max (ms) | 1120.2 | 1241.4 | 924.7 |

## 90718ff -> candidate

- changed sample-engine results: 5
- unified verdicts weaker than the baseline: 0
- flagged by the baseline, SAFE now: 0

  - `L40` (benign, unified): SAFE -> UNABLE_TO_SCAN; removed -; added -
  - `L46` (benign, unified): SAFE -> UNABLE_TO_SCAN; removed -; added -
  - `L47` (benign, unified): SAFE -> UNABLE_TO_SCAN; removed -; added -
  - `CD01` (benign, unified): SAFE -> UNABLE_TO_SCAN; removed -; added -
  - `CH05` (benign, unified): SAFE -> UNABLE_TO_SCAN; removed -; added -

## 840a300 -> candidate

- changed sample-engine results: 0
- unified verdicts weaker than the baseline: 0
- flagged by the baseline, SAFE now: 0


## Peak memory, candidate unified engine (one fresh process per sample)

- after loading scanners: 0.0
- peak over the corpus: 0.0 (sample `D1`)
- median per sample: 0.0
