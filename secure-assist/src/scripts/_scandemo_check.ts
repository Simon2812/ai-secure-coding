import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/Users/משתמש/Desktop/test/scan-demo';
const WEIGHTS: Record<string, number> = {
  'CWE-89': 30, 'CWE-78': 30, 'CWE-22': 20, 'CWE-321': 20,
  'CWE-259': 15, 'CWE-787': 15, 'CWE-327': 10, 'CWE-328': 10,
  'CWE-416': 10, 'CWE-190': 10,
};

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(full));
    else if (/\.(py|java|c|h|cpp|cc)$/i.test(e.name)) out.push(full);
  }
  return out;
}

async function main() {
  await initAstAnalyzer();
  const files = walk(ROOT);
  const scores: number[] = [];
  console.log(`\n${'File'.padEnd(30)}${'Score'.padEnd(8)}Findings`);
  console.log('─'.repeat(70));
  for (const f of files.sort()) {
    const code = fs.readFileSync(f, 'utf-8');
    const findings = astAnalyzeCode(code, f);
    const deduction = findings.reduce((s, x) => s + (WEIGHTS[x.cweId] ?? 10), 0);
    const score = Math.max(0, 100 - deduction);
    scores.push(score);
    const rel = path.relative(ROOT, f).replace(/\\/g, '/');
    const cwes = findings.map(x => `${x.cweId}@L${x.line}`).join(', ') || '(clean)';
    console.log(`${rel.padEnd(30)}${String(score).padEnd(8)}${cwes}`);
  }
  const project = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
  console.log('─'.repeat(70));
  console.log(`PROJECT SCORE: ${project}   (${files.length} files)`);
}
main().catch(console.error);
