import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

const REPO = 'C:/Users/drozh/asc-main-dataset/dataset/synthetic/CWE-22/java';

async function main() {
  await initAstAnalyzer();

  const tests = [
    // Pattern 1: regex whitelist guard (!var.matches(...) → throw)
    { file: `${REPO}/CWE-22-java-81.java`, expect: 'TN', desc: '!matches guard (direct)' },
    { file: `${REPO}/CWE-22-java-85.java`, expect: 'TN', desc: '!matches guard (direct)' },
    { file: `${REPO}/CWE-22-java-91.java`, expect: 'TN', desc: '!matches guard (in helper)' },
    // Pattern 2: Path.getFileName() path stripping
    { file: `${REPO}/CWE-22-java-82.java`, expect: 'TN', desc: 'getFileName() strip' },
    { file: `${REPO}/CWE-22-java-86.java`, expect: 'TN', desc: 'getFileName() strip' },
    { file: `${REPO}/CWE-22-java-92.java`, expect: 'TN', desc: 'getFileName() in helper' },
    { file: `${REPO}/CWE-22-java-97.java`, expect: 'TN', desc: 'getFileName() in helper' },
    // Pattern 3: contains blacklist guard (var.contains("..") → throw)
    { file: `${REPO}/CWE-22-java-83.java`, expect: 'TN', desc: 'contains blacklist (direct)' },
    { file: `${REPO}/CWE-22-java-87.java`, expect: 'TN', desc: 'contains blacklist (direct)' },
    { file: `${REPO}/CWE-22-java-93.java`, expect: 'TN', desc: 'contains blacklist (in helper)' },
    // Pattern 4: normalize+startsWith canonical check (harder — skipped for now)
    { file: `${REPO}/CWE-22-java-84.java`, expect: 'TN', desc: 'normalize+startsWith (direct)' },
    { file: `${REPO}/CWE-22-java-88.java`, expect: 'TN', desc: 'normalize+startsWith (in helper)' },
    { file: `${REPO}/CWE-22-java-94.java`, expect: 'TN', desc: 'normalize+startsWith (in helper)' },
    { file: `${REPO}/CWE-22-java-95.java`, expect: 'TN', desc: 'normalize+startsWith (in helper)' },
    { file: `${REPO}/CWE-22-java-98.java`, expect: 'TN', desc: 'normalize+startsWith (in helper)' },
    // Pattern 5: constant Map.get(key) whitelist lookup
    { file: `${REPO}/CWE-22-java-89.java`, expect: 'TN', desc: 'THEMES.get(key) whitelist' },
    { file: `${REPO}/CWE-22-java-96.java`, expect: 'TN', desc: 'PROFILES.get(key) whitelist' },
    { file: `${REPO}/CWE-22-java-99.java`, expect: 'TN', desc: 'MODULES.get(key) whitelist' },
    // Others
    { file: `${REPO}/CWE-22-java-90.java`, expect: 'TN', desc: 'sanitize() with replace' },
  ];

  let pass = 0, fail = 0;
  for (const t of tests) {
    if (!fs.existsSync(t.file)) { console.log(`SKIP (not found): ${t.file}`); continue; }
    const code = fs.readFileSync(t.file, 'utf-8');
    const findings = astAnalyzeCode(code, t.file);
    const hasCwe22 = findings.some(f => f.cweId === 'CWE-22');
    const got = hasCwe22 ? 'TP' : 'TN';
    const ok = got === t.expect;
    const extra = !ok ? ` [${findings.map(f => f.cweId + ': ' + f.message.slice(0, 60)).join('; ')}]` : '';
    console.log(`${ok ? '✓' : '✗'} ${t.expect}→${got} ${t.desc} [${t.file.split('/').pop()}]${extra}`);
    if (ok) pass++; else fail++;
  }
  console.log(`\n${pass} passed, ${fail} failed`);
}
main().catch(console.error);
