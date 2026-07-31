import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
async function main() {
  await initAstAnalyzer();
  for (const f of ['goodg2b_only.c','goodb2g_only.c']) {
    const code = fs.readFileSync('C:/temp/'+f, 'utf-8');
    const findings = astAnalyzeCode(code, f);
    console.log(`${f}: ${findings.length} findings ${findings.map(x=>x.cweId+'@L'+x.line).join(',')}`);
  }
}
main().catch(console.error);
