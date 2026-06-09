import {initAstAnalyzer, astAnalyzeCode} from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function main() {
  await initAstAnalyzer();

  const javaMetaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-22/java');
  const pyMetaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-22/python');

  let fps = 0, tns = 0;

  for (const dir of [javaMetaDir, pyMetaDir]) {
    for (const file of fs.readdirSync(dir).sort()) {
      const meta = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf-8'));
      if (meta.vulnerabilities.length > 0) continue; // skip vulnerable

      const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ''));
      if (!fs.existsSync(codePath)) continue;

      const code = fs.readFileSync(codePath, 'utf-8');
      const findings = astAnalyzeCode(code, codePath);

      if (findings.length > 0) {
        fps++;
        const cwes = findings.map(f => `${f.cweId}: ${f.message.substring(0, 60)}`).join(' | ');
        console.log(`FP: ${meta.id} → ${cwes}`);
      } else {
        tns++;
        // console.log(`TN: ${meta.id}`);
      }
    }
  }

  console.log(`\nTotal safe: ${fps + tns}, FPs: ${fps}, TNs: ${tns}`);
}
main().catch(console.error);
