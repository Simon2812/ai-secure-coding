import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  for (const f of ['Original.java', 'SimpleName.java']) {
    const code = fs.readFileSync(`C:/temp/fqn-test/${f}`, 'utf-8');
    const findings = astAnalyzeCode(code, f);
    const cwe22 = findings.filter(x => x.cweId === 'CWE-22');
    console.log(`${f.padEnd(16)} total=${findings.length}  CWE-22=${cwe22.length}  ${cwe22.map(x=>'L'+x.line).join(',')}`);
  }
}
main().catch(console.error);
