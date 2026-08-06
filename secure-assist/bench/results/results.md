
## Benchmark results

Cases scored: 2291 of 2298

7 cases excluded from all columns so every configuration is scored on the same set:
  - 7 — model server rejected its own output (HTTP 500)
Mean inference time: 6.1s per case


| Suite / category | Config | TPR | FPR | Youden | Precision | F1 | TP | FN | FP | TN |
|---|---|---|---|---|---|---|---|---|---|---|
| juliet/CWE-190 | Static | 59.4% | 27.1% | 32.4 | 52.3% | 55.6% | 101 | 69 | 92 | 248 |
|  | Model | 42.9% | 0.0% | 42.9 | 100.0% | 60.1% | 73 | 97 | 0 | 340 |
|  | Hybrid | 62.4% | 27.1% | 35.3 | 53.5% | 57.6% | 106 | 64 | 92 | 248 |
| juliet/CWE-416 | Static | 94.4% | 0.0% | 94.4 | 100.0% | 97.1% | 34 | 2 | 0 | 72 |
|  | Model | 94.4% | 0.0% | 94.4 | 100.0% | 97.1% | 34 | 2 | 0 | 72 |
|  | Hybrid | 94.4% | 0.0% | 94.4 | 100.0% | 97.1% | 34 | 2 | 0 | 72 |
| juliet/CWE-787 | Static | 35.9% | 34.8% | 1.1 | 49.2% | 41.5% | 61 | 109 | 63 | 118 |
|  | Model | 37.1% | 2.2% | 34.8 | 94.0% | 53.2% | 63 | 107 | 4 | 177 |
|  | Hybrid | 56.5% | 34.8% | 21.7 | 60.4% | 58.4% | 96 | 74 | 63 | 118 |
| owasp/cmdi | Static | 93.2% | 60.0% | 33.2 | 60.4% | 73.3% | 96 | 7 | 63 | 42 |
|  | Model | 46.6% | 21.0% | 25.6 | 68.6% | 55.5% | 48 | 55 | 22 | 83 |
|  | Hybrid | 93.2% | 60.0% | 33.2 | 60.4% | 73.3% | 96 | 7 | 63 | 42 |
| owasp/crypto | Static | 100.0% | 0.0% | 100.0 | 100.0% | 100.0% | 119 | 0 | 0 | 106 |
|  | Model | 100.0% | 0.0% | 100.0 | 100.0% | 100.0% | 119 | 0 | 0 | 106 |
|  | Hybrid | 100.0% | 0.0% | 100.0 | 100.0% | 100.0% | 119 | 0 | 0 | 106 |
| owasp/hash | Static | 69.2% | 0.0% | 69.2 | 100.0% | 81.8% | 83 | 37 | 0 | 102 |
|  | Model | 69.2% | 0.0% | 69.2 | 100.0% | 81.8% | 83 | 37 | 0 | 102 |
|  | Hybrid | 69.2% | 0.0% | 69.2 | 100.0% | 81.8% | 83 | 37 | 0 | 102 |
| owasp/pathtraver | Static | 84.7% | 47.4% | 37.3 | 60.6% | 70.6% | 83 | 15 | 54 | 60 |
|  | Model | 85.7% | 50.0% | 35.7 | 59.6% | 70.3% | 84 | 14 | 57 | 57 |
|  | Hybrid | 91.8% | 55.3% | 36.6 | 58.8% | 71.7% | 90 | 8 | 63 | 51 |
| owasp/sqli | Static | 60.9% | 32.5% | 28.4 | 68.2% | 64.3% | 148 | 95 | 69 | 143 |
|  | Model | 93.8% | 74.1% | 19.8 | 59.2% | 72.6% | 228 | 15 | 157 | 55 |
|  | Hybrid | 94.2% | 74.1% | 20.2 | 59.3% | 72.8% | 229 | 14 | 157 | 55 |
| **Overall** | Static | 68.5% | 27.7% | 40.8 | 68.0% | 68.2% | 725 | 334 | 341 | 891 |
|  | Model | 69.1% | 19.5% | 49.6 | 75.3% | 72.1% | 732 | 327 | 240 | 992 |
|  | Hybrid | 80.5% | 35.6% | 45.0 | 66.1% | 72.6% | 853 | 206 | 438 | 794 |

### What the model changed

- Recovered 128 vulnerable cases the static analyzer missed
- Introduced 97 false positives on safe cases the static analyzer got right
- Net Youden change: +4.2 points (40.8 → 45.0)

The Model column is reported for completeness only. The model receives the static findings as input, exactly as it does in the extension, so it is not an independent detector and must not be read as one.

### Method notes

- Test cases whose family appears in the model's fine-tuning set are excluded.
- Comments are stripped and verdict-bearing identifiers renamed, so neither configuration can read the answer from Juliet's `POTENTIAL FLAW` / `FIX` annotations or from the OWASP servlet path.
- Both configurations receive byte-identical input; the only difference is whether the model is consulted.
- Juliet is scored per function (`bad` positive, `goodG2B` / `goodB2G` negative) because each file contains both the flaw and its fix.
- A detection counts when the reported CWE is in the case's accept set; CWE-787 also accepts CWE-190 (our rules report size arithmetic that way) and CWE-327/CWE-328 are accepted interchangeably.