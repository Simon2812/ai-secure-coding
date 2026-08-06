
## RealVuln — real-world Python applications

21 repositories, 465 Python files scored.
4 files excluded from both columns (model returned malformed JSON); their labels are removed from the denominator so both configurations are scored on an identical file set.

| Config | Recall | Trap FP rate | Precision | F1 | TP | FN | Traps tripped | Unlabelled findings |
|---|---|---|---|---|---|---|---|---|
| Static | 67.2% | 21.2% | 47.0% | 55.3% | 86 | 42 | 11/52 | 86 |
| Hybrid | 75.8% | 26.9% | 32.7% | 45.6% | 97 | 31 | 14/52 | 186 |