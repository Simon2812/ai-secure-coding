import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function main() {
  await initAstAnalyzer();
  const metaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-259');

  for (const lang of fs.readdirSync(metaDir)) {
    const langDir = path.join(metaDir, lang);
    if (!fs.statSync(langDir).isDirectory()) continue;
    for (const file of fs.readdirSync(langDir).sort()) {
      const meta = JSON.parse(fs.readFileSync(path.join(langDir, file), 'utf-8'));
      if (meta.vulnerabilities.length === 0) continue;
      const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ''));
      if (!fs.existsSync(codePath)) continue;
      const code = fs.readFileSync(codePath, 'utf-8');
      const findings = astAnalyzeCode(code, codePath);
      if (findings.length === 0) {
        console.log(`FN: ${meta.id} [${lang}]`);
      }
    }
  }
}
main().catch(console.error);
