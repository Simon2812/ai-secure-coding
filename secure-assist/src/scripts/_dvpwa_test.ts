import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const code = fs.readFileSync('C:/temp/dvpwa_student.py', 'utf-8');
  const findings = astAnalyzeCode(code, 'dvpwa_student.py');
  console.log(`\nFindings: ${findings.length}`);
  if (findings.length === 0) {
    console.log('No findings — analyzer does NOT fire.');
  } else {
    findings.forEach(f => console.log(`  ${f.cweId}  line ${f.line}  ${f.message}`));
  }
}
main().catch(console.error);
