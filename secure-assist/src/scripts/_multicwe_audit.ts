import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/ai-secure-main';
const META = path.join(ROOT, 'dataset/metadata/MULTI-CWE');

async function main() {
  await initAstAnalyzer();

  let tp = 0, fn = 0, fp = 0, tn = 0;

  for (const lang of fs.readdirSync(META)) {
    const langDir = path.join(META, lang);
    if (!fs.statSync(langDir).isDirectory()) continue;

    for (const f of fs.readdirSync(langDir).sort()) {
      const meta = JSON.parse(fs.readFileSync(path.join(langDir, f), 'utf-8'));
      const codePath = path.join(ROOT, meta.path.replace(/^\//, ''));
      if (!fs.existsSync(codePath)) continue;

      const code = fs.readFileSync(codePath, 'utf-8');
      const findings = astAnalyzeCode(code, codePath);
      const isVuln = meta.vulnerabilities.length > 0;
      const hasFindings = findings.length > 0;
      const cwes = meta.vulnerabilities.map((v: any) => v.cwe).join(', ');
      const found = findings.map((f: any) => f.cweId).filter((v: any, i: any, a: any) => a.indexOf(v) === i).join(', ');

      if (isVuln && hasFindings)   { tp++; }
      else if (isVuln && !hasFindings) { fn++; console.log(`FN: ${meta.id} | labeled: ${cwes}`); }
      else if (!isVuln && hasFindings) { fp++; console.log(`FP: ${meta.id} | labeled: SAFE | found: ${found}`); }
      else                             { tn++; console.log(`TN: ${meta.id} | labeled: SAFE`); }
    }
  }

  console.log(`\nTP:${tp}  FN:${fn}  FP:${fp}  TN:${tn}`);
  console.log(`Detection: ${(tp/(tp+fn)*100).toFixed(1)}%  FP rate: ${(fp/(fp+tn)*100).toFixed(1)}%`);
}
main().catch(console.error);
