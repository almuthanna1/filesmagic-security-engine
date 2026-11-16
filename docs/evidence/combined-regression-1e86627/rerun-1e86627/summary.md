# Combined-build accuracy regression

Windows-11-10.0.26300-SP0, 1 trials per scan. Every sample is benign or an inert synthetic construction (no malware).

- **candidate**: `1e86627560f8` (dirty: False), pypdf 7.0.1

| Measure | candidate |
|---|---|
| Samples | 252 |
| Unified SAFE | 153 |
| Unified UNABLE_TO_SCAN | 5 |
| Unified SUSPICIOUS | 85 |
| Unified MALICIOUS | 9 |
| detection TP | 55 |
| detection FP | 9 |
| detection TN | 134 |
| detection FN | 0 |
| detection precision | 0.8594 |
| detection recall | 1.0 |
| detection f1 | 0.9244 |
| detection false_positive_rate | 0.0629 |
| gate TP | 55 |
| gate FP | 14 |
| gate TN | 129 |
| gate FN | 0 |
| gate precision | 0.7971 |
| gate recall | 1.0 |
| gate f1 | 0.8871 |
| gate false_positive_rate | 0.0979 |
| Scanner failures (sample, scanner) | 1 |
| Worker errors | 0 |
| Incomplete coverage (samples) | 14 |
| Case mismatches vs frozen | 0 |
| Not deterministic | 0 |
| Unified latency median (ms) | 528.6 |
| Unified latency p95 (ms) | 713.1 |
| Unified latency max (ms) | 982.6 |
