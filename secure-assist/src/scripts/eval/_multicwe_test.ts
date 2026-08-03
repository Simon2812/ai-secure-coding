import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const filePath = 'C:/temp/ai-secure-main/dataset/synthetic/MULTI-CWE/python/MULTI-CWE-python-01.py';
  const code = fs.readFileSync(filePath, 'utf-8');
  const findings = astAnalyzeCode(code, filePath);
  if (findings.length === 0) {
    console.log('No findings.');
  } else {
    for (const f of findings) {
      console.log(`${f.cweId} | line ${f.line} | ${f.message}`);
    }
  }
}
main().catch(console.error);
