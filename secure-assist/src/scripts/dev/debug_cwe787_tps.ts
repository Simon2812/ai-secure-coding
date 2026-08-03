import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function main() {
  await initAstAnalyzer();

  const metaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-787');
  let tp_strcpy = 0, fn_strcpy = 0;

  for (const file of fs.readdirSync(metaDir).sort()) {
    const meta = JSON.parse(fs.readFileSync(path.join(metaDir, file), 'utf-8'));
    if (meta.vulnerabilities.length === 0) continue; // skip safe files

    const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ''));
    if (!fs.existsSync(codePath)) continue;

    const code = fs.readFileSync(codePath, 'utf-8');
    const has787 = code.includes('strcpy') || code.includes('strcat');
    if (!has787) continue;

    const findings = astAnalyzeCode(code, codePath);
    const detects787 = findings.some(f => f.cweId === 'CWE-787' && f.message.includes('strcpy'));

    console.log(`${meta.id}: strcpy/strcat in code, detected=${detects787}`);
    if (detects787) tp_strcpy++; else fn_strcpy++;
  }
  console.log(`\nstrcpy-based TPs: ${tp_strcpy}, FNs (missed): ${fn_strcpy}`);
}
main().catch(console.error);
