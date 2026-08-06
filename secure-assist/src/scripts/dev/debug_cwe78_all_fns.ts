import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function checkCwe(cwe: string) {
  const metaDir = path.join(REPO_ROOT, `dataset/metadata/${cwe}`);
  if (!fs.existsSync(metaDir)) return;

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
      const hasTarget = findings.some(f => f.cweId === cwe);

      if (!hasTarget) {
        console.log(`FN: ${meta.id} (findings: ${findings.map(f=>f.cweId).join(', ')||'none'})`);
      }
    }
  }
}

async function main() {
  await initAstAnalyzer();
  console.log('=== CWE-78 FNs ===');
  await checkCwe('CWE-78');
}
main().catch(console.error);
