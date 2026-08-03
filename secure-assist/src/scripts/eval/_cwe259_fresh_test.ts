import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

const TEST_FILES: { path: string; expectVuln: boolean }[] = [
  // Python
  { path: 'C:/temp/cwe259-fresh/python/vuln_db_conn.py',       expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/python/vuln_api_key.py',       expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/python/vuln_default_arg.py',   expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/python/vuln_smtp.py',          expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/python/safe_env_password.py',  expectVuln: false },
  { path: 'C:/temp/cwe259-fresh/python/safe_config_password.py', expectVuln: false },
  // Java
  { path: 'C:/temp/cwe259-fresh/java/VulnJdbcPassword.java',   expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/java/VulnLdapPassword.java',   expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/java/SafePropertiesPassword.java', expectVuln: false },
  // C
  { path: 'C:/temp/cwe259-fresh/c/vuln_strcmp_password.c',     expectVuln: true  },
  { path: 'C:/temp/cwe259-fresh/c/safe_getenv_password.c',     expectVuln: false },
];

async function main() {
  await initAstAnalyzer();
  let passed = 0, failed = 0;

  for (const { path: filePath, expectVuln } of TEST_FILES) {
    const code = fs.readFileSync(filePath, 'utf-8');
    const findings = astAnalyzeCode(code, filePath);
    const has259 = findings.some(f => f.cweId === 'CWE-259');
    const ok = has259 === expectVuln;

    const label    = ok ? '✓ PASS' : '✗ FAIL';
    const expected = expectVuln ? 'VULN' : 'SAFE';
    const got      = has259    ? 'VULN' : 'CLEAN';
    console.log(`${label}  [${expected}→${got}]  ${filePath.split('/').slice(-2).join('/')}`);
    if (!ok) {
      const details = findings
        .filter(f => f.cweId === 'CWE-259')
        .map(f => `         line ${f.line}: ${f.message}`)
        .join('\n');
      if (details) console.log(details);
      else if (expectVuln) console.log('         (no CWE-259 findings — missed)');
    }
    if (ok) passed++; else failed++;
  }

  console.log(`\n${passed}/${TEST_FILES.length} passed  |  ${failed} failed`);
}
main().catch(console.error);
