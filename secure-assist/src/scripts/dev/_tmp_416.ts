import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function main() {
  await initAstAnalyzer();
  const metaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-416');

  for (const file of fs.readdirSync(metaDir).sort()) {
    const meta = JSON.parse(fs.readFileSync(path.join(metaDir, file), 'utf-8'));
    if (meta.vulnerabilities.length === 0) continue;
    const relPath = meta.path.startsWith('/') ? meta.path.slice(1) : meta.path;
    const codePath = path.join(REPO_ROOT, relPath);
    if (!fs.existsSync(codePath)) continue;
    const code = fs.readFileSync(codePath, 'utf-8');
    const findings = astAnalyzeCode(code, codePath);
    if (findings.length === 0) {
      console.log('FN: ' + meta.id + ' [' + meta.language + ']');
    } else {
      const cwes = [...new Set(findings.map((f: any) => f.cweId))].join(',');
      console.log('TP: ' + meta.id + ' [' + meta.language + '] -> ' + cwes);
    }
  }
}
main().catch(console.error);