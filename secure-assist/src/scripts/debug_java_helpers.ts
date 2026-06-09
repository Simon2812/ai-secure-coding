import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

const REPO = 'C:/Users/drozh/asc-main-dataset/dataset/normalized/CWE-22/java';

async function main() {
  await initAstAnalyzer();

  const tests = [
    // Safe files that should be TN (no findings)
    { file: `${REPO}/CWE-22-java-64.java`, expect: 'TN', desc: 'if-else dead branch (local)' },
    { file: `${REPO}/CWE-22-java-77.java`, expect: 'TN', desc: 'if-else dead branch in helper' },
    { file: `${REPO}/CWE-22-java-80.java`, expect: 'TN', desc: 'ternary dead branch in helper' },
    // Vulnerable files that must still be TP
    { file: `${REPO}/CWE-22-java-11.java`, expect: 'TP', desc: 'helper returns tainted (TP)' },
    { file: `${REPO}/CWE-22-java-14.java`, expect: 'TP', desc: 'helper returns tainted (TP)' },
    { file: `${REPO}/CWE-22-java-01.java`, expect: 'TP', desc: 'direct path traversal (TP)' },
    { file: `${REPO}/CWE-22-java-02.java`, expect: 'TP', desc: 'direct path traversal (TP)' },
    { file: `${REPO}/CWE-22-java-05.java`, expect: 'TP', desc: 'direct path traversal (TP)' },
  ];

  let pass = 0, fail = 0;
  for (const t of tests) {
    if (!fs.existsSync(t.file)) { console.log(`SKIP (not found): ${t.file}`); continue; }
    const code = fs.readFileSync(t.file, 'utf-8');
    const findings = astAnalyzeCode(code, t.file);
    const hasCwe22 = findings.some(f => f.cweId === 'CWE-22');
    const got = hasCwe22 ? 'TP' : 'TN';
    const ok = got === t.expect;
    console.log(`${ok ? '✓' : '✗'} ${t.expect}→${got} ${t.desc} [${t.file.split('/').pop()}]`);
    if (ok) pass++; else fail++;
  }
  console.log(`\n${pass} passed, ${fail} failed`);
}
main().catch(console.error);
