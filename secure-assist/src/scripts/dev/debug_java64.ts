import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const code = fs.readFileSync('C:/Users/drozh/asc-main-dataset/dataset/normalized/CWE-22/java/CWE-22-java-64.java', 'utf-8');
  const findings = astAnalyzeCode(code, 'test.java');
  console.log('java-64 findings:', findings.length === 0 ? 'NONE (TN!)' : findings.map(f => f.cweId + ': ' + f.message).join('\n'));
}
main().catch(console.error);
