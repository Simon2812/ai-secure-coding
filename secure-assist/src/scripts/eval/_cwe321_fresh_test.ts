import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

const TEST_FILES: { path: string; expectVuln: boolean }[] = [
  // Python
  { path: 'C:/temp/cwe321-fresh/python/vuln_aes_literal.py',  expectVuln: true  },
  { path: 'C:/temp/cwe321-fresh/python/vuln_jwt_secret.py',   expectVuln: true  },
  { path: 'C:/temp/cwe321-fresh/python/vuln_fernet_key.py',   expectVuln: true  },
  { path: 'C:/temp/cwe321-fresh/python/safe_env_key.py',      expectVuln: false },
  { path: 'C:/temp/cwe321-fresh/python/safe_kdf_key.py',      expectVuln: false },
  // Java
  { path: 'C:/temp/cwe321-fresh/java/VulnHardcodedAES.java',  expectVuln: true  },
  { path: 'C:/temp/cwe321-fresh/java/VulnHardcodedString.java', expectVuln: true },
  { path: 'C:/temp/cwe321-fresh/java/SafeEnvKey.java',        expectVuln: false },
  // C
  { path: 'C:/temp/cwe321-fresh/c/vuln_hardcoded.c',          expectVuln: true  },
  { path: 'C:/temp/cwe321-fresh/c/safe_runtime_key.c',        expectVuln: false },
];

async function main() {
  await initAstAnalyzer();
  let passed = 0, failed = 0;

  for (const { path: filePath, expectVuln } of TEST_FILES) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const findings = astAnalyzeCode(code, filePath);
    const has321 = findings.some(f => f.cweId === 'CWE-321');
    const ok = has321 === expectVuln;

    const label = ok ? '✓ PASS' : '✗ FAIL';
    const expected = expectVuln ? 'VULN' : 'SAFE';
    const got = has321 ? 'VULN' : 'CLEAN';
    console.log(`${label}  [${expected}→${got}]  ${filePath.split('/').slice(-2).join('/')}`);
    if (!ok) {
      const details = findings.filter(f => f.cweId === 'CWE-321').map(f => `         line ${f.line}: ${f.message}`).join('\n');
      if (details) console.log(details);
    }
    if (ok) passed++; else failed++;
  }

  console.log(`\n${passed}/${TEST_FILES.length} passed  |  ${failed} failed`);
}
main().catch(console.error);
