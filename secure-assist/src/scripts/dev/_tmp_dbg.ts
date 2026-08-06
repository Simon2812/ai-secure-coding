import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const path = 'C:/Users/drozh/asc-main-dataset/dataset/synthetic/CWE-416/CWE-416-20.c';
  const code = fs.readFileSync(path, 'utf-8');
  const findings = astAnalyzeCode(code, path);
  findings.forEach((f: any) => console.log(f.cweId, f.ruleId, f.message));
}
main().catch(console.error);