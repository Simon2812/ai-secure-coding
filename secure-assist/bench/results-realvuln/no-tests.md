
## RealVuln — effect of excluding test files

Test suites are scanned because RealVuln clones whole repositories, but the ground truth does not label them — a fixture logging in with a fixed password is not a vulnerability. No in-scope label sits in a test file, so excluding them cannot cost a true positive.

| Configuration | Recall | Precision | F1 | F3 | TP | FN | Unlabelled | Files skipped |
|---|---|---|---|---|---|---|---|---|
| Static, all files | 67.2% | 47.0% | 55.3 | 64.4 | 86 | 42 | 86 | 0 |
| Static, no tests | 67.2% | 67.7% | 67.5 | 67.2 | 86 | 42 | 30 | 100 |
| Hybrid, all files | 75.8% | 32.7% | 45.6 | 66.9 | 97 | 31 | 186 | 0 |
| Hybrid, no tests | 75.8% | 49.5% | 59.9 | 72.0 | 97 | 31 | 85 | 100 |

Static precision 47.0% to 67.7%, hybrid 32.7% to 49.5%. Recall is unchanged in both cases, as expected.

For comparison, findings reported inside test files by the scanners RealVuln published: Semgrep 0, Claude Opus 5 0, GPT-5.5 0, Kolega 0, Snyk 12, SonarQube 71.