
## RealVuln — like-for-like comparison

All tools scored on the identical subset: 22 repositories, only the ten CWEs SecureAssist covers, only .py files, same ±10-line matcher, same 4 excluded files.

| Tool | Recall | Precision | F1 | F3 | TP | FN | Traps tripped | Unlabelled |
|---|---|---|---|---|---|---|---|---|
| **SecureAssist (hybrid)** | 75.8% | 32.7% | 45.6 | 66.9 | 97 | 31 | 14/52 | 186 |
| **SecureAssist (static)** | 67.2% | 47.0% | 55.3 | 64.4 | 86 | 42 | 11/52 | 86 |
| claude-opus-5-cc-agentic-v1 | 61.7% | 86.8% | 72.1 | 63.6 | 79 | 49 | 6/52 | 6 |
| kolega-devsec-max-v0.0.1 | 55.5% | 86.6% | 67.6 | 57.5 | 71 | 57 | 7/52 | 4 |
| gpt-5.5-agentic-v1 | 53.1% | 88.3% | 66.3 | 55.3 | 68 | 60 | 6/52 | 3 |
| gemini-3.1-pro-agentic-v1 | 51.6% | 89.2% | 65.3 | 53.8 | 66 | 62 | 7/52 | 1 |
| claude-sonnet-4-6-agentic-v1 | 48.4% | 91.2% | 63.3 | 50.8 | 62 | 66 | 6/52 | 0 |
| deepseek-v4-pro-agentic-v1 | 47.7% | 87.1% | 61.6 | 49.9 | 61 | 67 | 6/52 | 3 |
| qwen-3.5-397b-agentic-v1 | 46.1% | 77.6% | 57.8 | 48.0 | 59 | 69 | 10/52 | 7 |
| semgrep | 26.6% | 79.1% | 39.8 | 28.5 | 34 | 94 | 3/52 | 6 |
| snyk | 14.1% | 64.3% | 23.1 | 15.3 | 18 | 110 | 4/52 | 6 |
| sonarqube | 6.3% | 80.0% | 11.6 | 6.9 | 8 | 120 | 0/52 | 2 |

F3 weights recall nine times precision, matching RealVuln's headline metric. Note these figures are NOT comparable to RealVuln's published leaderboard, which scores all 796 findings across every CWE; this table is restricted to the ten CWEs SecureAssist implements.