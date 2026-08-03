import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/ai-secure-main';
const META = path.join(ROOT, 'dataset/metadata/CWE-259');

async function main() {
  await initAstAnalyzer();

  for (const lang of fs.readdirSync(META)) {
    const langDir = path.join(META, lang);
    if (!fs.statSync(langDir).isDirectory()) continue;

    for (const f of fs.readdirSync(langDir).sort()) {
      const meta = JSON.parse(fs.readFileSync(path.join(langDir, f), 'utf-8'));
      if (meta.vulnerabilities.length > 0) continue; // safe files only

      const codePath = path.join(ROOT, meta.path.replace(/^\//, ''));
      if (!fs.existsSync(codePath)) continue;

      const code = fs.readFileSync(codePath, 'utf-8');
      const findings = astAnalyzeCode(code, codePath);
      const fps = findings.filter(f => f.cweId === 'CWE-259' || f.cweId === 'CWE-321');
      if (fps.length > 0) {
        console.log(`FP: ${meta.id} (${lang})`);
        for (const fp of fps) console.log(`  ${fp.cweId} line ${fp.line}: ${fp.message}`);
      }
    }
  }
}
main().catch(console.error);
