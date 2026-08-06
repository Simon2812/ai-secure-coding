import {initAstAnalyzer, astAnalyzeCode} from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
async function main() {
  await initAstAnalyzer();
  const code = fs.readFileSync('C:/Users/drozh/asc-main-dataset/dataset/synthetic/CWE-22/python/CWE-22-python-82.py', 'utf-8');
  const findings = astAnalyzeCode(code, 'test.py');
  console.log('findings:', findings.length);
  for (const f of findings) console.log(' ', f.cweId, f.ruleId, JSON.stringify(f.message));
}
main().catch(console.error);
