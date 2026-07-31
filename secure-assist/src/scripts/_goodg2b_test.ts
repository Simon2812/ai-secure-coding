import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const code = fs.readFileSync('C:/temp/goodg2b_only.c', 'utf-8');
  const findings = astAnalyzeCode(code, 'goodg2b_only.c');
  console.log(`Findings: ${findings.length}`);
  findings.forEach(f => console.log(`  ${f.cweId}  line ${f.line}  ${f.message}`));
  if (findings.length === 0) console.log('  (analyzer does NOT fire — you were right)');
}
main().catch(console.error);
