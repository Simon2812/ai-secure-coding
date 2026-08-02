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

## Known limitations (documented, not scheduled)

- **Java validation guards are matched by variable *name*, file-wide — not by data flow.**
  `applyJavaValidationGuards` (`ast/java.ts`) walks the whole file and removes any guarded
  identifier from a global taint set. Consequences, both reproducible:
  1. A guard on a same-named variable in an *unrelated* method suppresses a real finding.
     Verified: `buildPath(String name)` unguarded + `auditLabel(String name)` guarded
     ⇒ CWE-22 silently suppressed.
  2. The guard is accepted on shape alone (`matches()` + `throw`); the pattern is not checked
     for restrictiveness, so `name.matches(".*")` also suppresses.
  Not fixed deliberately: scoping guards to the enclosing method closes the false negative but
  reintroduces false positives on code that *was* correctly fixed in a helper (e.g. the
  FileService.java case), so it trades one error class for another. Same family as the
  cross-function SQL taint pollution fixed earlier via `buildLocalValueMap`.

## Model / IDE integration (branch: ASC-68-model-ide-integration)

- [x] Wire the extension to POST `{ code, analysis: static_findings }` to `http://localhost:8000/analyze`
- [x] Map returned `vulnerabilities[]` (cwe + fixes + start_line/end_line) to VSCode diagnostics
- [x] Wire "Apply Fix" using each fix's `origin` / `replacement`
- [x] Make the model endpoint URL configurable (`secureAssist.modelEndpoint`)

## Deep scan report (branch: ASC-69-deep-scan-report)

- [x] Deep Scan + Report (webview, folder tree, per-file scores, Verify→Fix, Export HTML)
- [x] Live mode (static analyzer on change, debounced; model on demand)
- [x] Score history + before/after session delta
- [x] Filters, CWE breakdown, self-contained theme
- [ ] Verify all files in a folder (one click, sequential, with cancel)
- [ ] Export findings as Markdown / JSON

## Later

- [ ] Combined analyzer + model evaluation (added detections / removed FPs) on OWASP + Juliet sample — for the paper
- [ ] `evaluator.py` hard-depends on `secure-assist/` being present — consider making the analyzer path optional so the API runs standalone
