import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

const TEST_FILES: { path: string; expectVuln: boolean }[] = [
  // C
  { path: 'C:/temp/cwe78-test/c/vuln_system.c',          expectVuln: true  },
  { path: 'C:/temp/cwe78-test/c/vuln_exec.c',            expectVuln: true  },
  { path: 'C:/temp/cwe78-test/c/safe_allowlist.c',       expectVuln: false },
  { path: 'C:/temp/cwe78-test/c/safe_literal.c',         expectVuln: false },
  // Java
  { path: 'C:/temp/cwe78-test/java/VulnRuntime.java',    expectVuln: true  },
  { path: 'C:/temp/cwe78-test/java/VulnProcessBuilder.java', expectVuln: true },
  { path: 'C:/temp/cwe78-test/java/SafeValidated.java',  expectVuln: false },
  { path: 'C:/temp/cwe78-test/java/SafeLiteral.java',    expectVuln: false },
  // Python
  { path: 'C:/temp/cwe78-test/python/vuln_subprocess.py', expectVuln: true },
  { path: 'C:/temp/cwe78-test/python/vuln_os_system.py', expectVuln: true  },
  { path: 'C:/temp/cwe78-test/python/safe_no_shell.py',  expectVuln: false },
  { path: 'C:/temp/cwe78-test/python/safe_allowlist.py', expectVuln: false },
];

async function main() {
  await initAstAnalyzer();

  let passed = 0;
  let failed = 0;

  for (const { path: filePath, expectVuln } of TEST_FILES) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const findings = astAnalyzeCode(code, filePath);
    const has78 = findings.some(f => f.cweId === 'CWE-78');
    const ok = has78 === expectVuln;

    const label = ok ? '✓ PASS' : '✗ FAIL';
    const expected = expectVuln ? 'VULN' : 'SAFE';
    const got = has78 ? 'VULN' : 'CLEAN';
    console.log(`${label}  [${expected}→${got}]  ${filePath.replace('C:/temp/cwe78-test/', '')}`);

    if (ok) passed++; else failed++;
  }

  console.log(`\n${passed}/12 passed  |  ${failed} failed`);
}
main().catch(console.error);
