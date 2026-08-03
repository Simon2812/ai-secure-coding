import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function main() {
  await initAstAnalyzer();

  const javaMetaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-78/java');
  let fns = 0, tps = 0;

  for (const file of fs.readdirSync(javaMetaDir).sort()) {
    const meta = JSON.parse(fs.readFileSync(path.join(javaMetaDir, file), 'utf-8'));
    if (meta.vulnerabilities.length === 0) continue; // skip safe files

    const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ''));
    if (!fs.existsSync(codePath)) continue;

    const code = fs.readFileSync(codePath, 'utf-8');
    const findings = astAnalyzeCode(code, codePath);
    const has78 = findings.some(f => f.cweId === 'CWE-78');

    if (!has78) {
      fns++;
      console.log(`FN: ${meta.id}`);
    } else {
      tps++;
    }
  }

  console.log(`\nTP: ${tps}, FN: ${fns}`);
}
main().catch(console.error);
