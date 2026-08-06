import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

const TEST_FILES: { path: string; expectVuln: boolean }[] = [
  // Python
  { path: 'C:/temp/cwe22-fresh/python/vuln_zip_slip.py',      expectVuln: true  },
  { path: 'C:/temp/cwe22-fresh/python/vuln_env_path.py',      expectVuln: true  },
  { path: 'C:/temp/cwe22-fresh/python/safe_realpath_check.py',expectVuln: false },
  { path: 'C:/temp/cwe22-fresh/python/safe_werkzeug.py',      expectVuln: false },
  // Java
  { path: 'C:/temp/cwe22-fresh/java/VulnServlet.java',        expectVuln: true  },
  { path: 'C:/temp/cwe22-fresh/java/SafeServlet.java',        expectVuln: false },
  { path: 'C:/temp/cwe22-fresh/java/SafeFileName.java',       expectVuln: false },
];

async function main() {
  await initAstAnalyzer();

  let passed = 0, failed = 0;

  for (const { path: filePath, expectVuln } of TEST_FILES) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const findings = astAnalyzeCode(code, filePath);
    const has22 = findings.some(f => f.cweId === 'CWE-22');
    const ok = has22 === expectVuln;

    const label = ok ? '✓ PASS' : '✗ FAIL';
    const expected = expectVuln ? 'VULN' : 'SAFE';
    const got = has22 ? 'VULN' : 'CLEAN';
    if (!ok) {
      const details = findings.map(f => `  ${f.cweId} line ${f.line}: ${f.message}`).join('\n');
      console.log(`${label}  [${expected}→${got}]  ${filePath.split('/').slice(-2).join('/')}`);
      if (details) console.log(details);
    } else {
      console.log(`${label}  [${expected}→${got}]  ${filePath.split('/').slice(-2).join('/')}`);
    }

    if (ok) passed++; else failed++;
  }

  console.log(`\n${passed}/${TEST_FILES.length} passed  |  ${failed} failed`);
}
main().catch(console.error);
