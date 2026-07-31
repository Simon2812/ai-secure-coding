# SecureAssist — TODO

## Analyzer

- [x] **Weak-hash detection dual-emits CWE-327 + CWE-328 — should return CWE-328 only.**
  DONE — all 6 sites now emit CWE-328 only for hashes; weak ciphers still emit CWE-327.
  Verified against the dataset: CWE-327 samples contain 0 hash cases, CWE-328 contains 76 —
  so the dual-emit never matched a label. real50 unchanged (CWE-327 and CWE-328 both 100%/0%).
  Currently, weak-hash rules (MD5/SHA-1) push a finding for *both* CWE-327 and CWE-328 via
  `for (const cweId of ["CWE-327", "CWE-328"])`. A weak hash is CWE-328 (Reversible One-Way
  Hash); the extra CWE-327 is incorrect and should be dropped for hash cases.
  Locations:
  - `secure-assist/src/scripts/ast/python.ts:173`
  - `secure-assist/src/scripts/ast/java.ts:81, 224, 247`
  - `secure-assist/src/scripts/ast/c.ts:268, 299`
  Note: the dual-emit was intentional ("dataset labels either CWE"). Before changing, confirm the
  dataset labels weak hashes as CWE-328, keep weak *cipher* (DES/RC4) as CWE-327 only, and re-run
  real50 / fresh50 / OWASP hash+crypto to confirm detection isn't lost.

## Model / IDE integration (branch: ASC-68-model-ide-integration)

- [ ] Wire the extension to POST `{ code, analysis: static_findings }` to `http://localhost:8000/analyze`
- [ ] Map returned `vulnerabilities[]` (cwe + fixes + start_line/end_line) to VSCode diagnostics
- [ ] Wire "Apply Fix" using each fix's `origin` / `replacement`
- [ ] Make the model endpoint URL configurable (VSCode setting)

## Later

- [ ] Combined analyzer + model evaluation (added detections / removed FPs) on OWASP + Juliet sample — for the paper
- [ ] Deep Scan + Report (webview, per-file scores, Verify→Fix, Export HTML)
- [ ] Live mode (static on change; model on new finding)
- [ ] `evaluator.py` hard-depends on `secure-assist/` being present — consider making the analyzer path optional so the API runs standalone
