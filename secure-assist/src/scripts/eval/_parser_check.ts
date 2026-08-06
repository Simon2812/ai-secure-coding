import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const p = 'C:/Users/משתמש/Desktop/test/scan-demo/native/parser.c';
  const findings = astAnalyzeCode(fs.readFileSync(p, 'utf-8'), p);
  console.log('parser.c:', findings.length
    ? findings.map(f => `${f.cweId}@L${f.line}`).join(', ')
    : '(clean)');
}
main().catch(console.error);
