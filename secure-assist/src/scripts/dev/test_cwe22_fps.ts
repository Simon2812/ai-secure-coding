import {initAstAnalyzer, astAnalyzeCode} from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const REPO_ROOT = 'C:/Users/drozh/asc-main-dataset';

async function main() {
  await initAstAnalyzer();
  
  // Check all safe CWE-22 files
  const javaMetaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-22/java');
  const pyMetaDir = path.join(REPO_ROOT, 'dataset/metadata/CWE-22/python');
  
  let fps = 0, tns = 0;
  
  for (const dir of [javaMetaDir, pyMetaDir]) {
    for (const file of fs.readdirSync(dir)) {
      const meta = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf-8'));
      if (meta.vulnerabilities.length > 0) continue; // skip vulnerable
      
      const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ''));
      if (!fs.existsSync(codePath)) continue;
      
      const code = fs.readFileSync(codePath, 'utf-8');
      const findings = astAnalyzeCode(code, codePath);
      const cwe22Findings = findings.filter(f => f.cweId === 'CWE-22');
      
      if (cwe22Findings.length > 0) {
        fps++;
        console.log(`FP: ${meta.id} → ${cwe22Findings.map(f => f.message).join('; ')}`);
      } else {
        tns++;
      }
    }
  }
  
  console.log(`\nTotal safe files: ${fps + tns}, FPs: ${fps}, TNs: ${tns}`);
}
main().catch(console.error);
