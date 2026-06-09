import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

function* iterMetaFiles(cwe: string): Generator<{ file: string; lang: string }> {
  const metaDir = path.join(REPO_ROOT, `dataset/metadata/${cwe}`);
  if (!fs.existsSync(metaDir)) return;
  for (const entry of fs.readdirSync(metaDir).sort()) {
    const fullPath = path.join(metaDir, entry);
    if (fs.statSync(fullPath).isDirectory()) {
      // Language subdirectory (CWE-22/java/, CWE-78/java/, etc.)
      for (const f of fs.readdirSync(fullPath).sort()) {
        if (f.endsWith('.json')) yield { file: path.join(fullPath, f), lang: entry };
      }
    } else if (entry.endsWith('.json')) {
      // Flat structure (CWE-787, CWE-416, etc.)
      yield { file: fullPath, lang: '' };
    }
  }
}

async function checkFPs(cwe: string) {
  let fpCount = 0;
  for (const { file, lang } of iterMetaFiles(cwe)) {
    const meta = JSON.parse(fs.readFileSync(file, 'utf-8'));
    if (meta.vulnerabilities.length > 0) continue; // skip vulnerable files

    const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ''));
    if (!fs.existsSync(codePath)) continue;

    const code = fs.readFileSync(codePath, 'utf-8');
    const findings = astAnalyzeCode(code, codePath);
    if (findings.length > 0) {
      fpCount++;
      const tag = lang ? `[${lang}]` : '';
      console.log(`FP ${tag}: ${meta.id} → ${findings.map(f => f.cweId + ': ' + f.message.slice(0, 70)).join(' | ')}`);
    }
  }
  console.log(`\nTotal FPs for ${cwe}: ${fpCount}`);
}

async function main() {
  await initAstAnalyzer();
  const cwe = process.argv[2] || 'CWE-787';
  console.log(`=== ${cwe} FPs ===`);
  await checkFPs(cwe);
}
main().catch(console.error);
