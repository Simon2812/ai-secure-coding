import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const code = fs.readFileSync('C:/temp/inter_proc_test.py', 'utf-8');
  const findings = astAnalyzeCode(code, 'inter_proc_test.py');
  console.log(`Findings: ${findings.length}`);
  findings.forEach(f => console.log(`  ${f.cweId} line ${f.line} — ${f.message}`));
  if (findings.length === 0) console.log('No findings — analyzer misses this.');
}
main().catch(console.error);
