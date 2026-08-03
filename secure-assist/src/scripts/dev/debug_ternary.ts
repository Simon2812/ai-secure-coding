import {initAstAnalyzer, astAnalyzeCode} from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import Parser from 'web-tree-sitter';

async function main() {
  await initAstAnalyzer();

  // Test the OWASP Java benchmark safe file
  const code = fs.readFileSync(
    'C:/Users/drozh/asc-main-dataset/dataset/normalized/CWE-22/java/CWE-22-java-61.java', 'utf-8'
  );
  
  // Find and print node types around the ternary
  const idx = code.indexOf('? "notes.txt"');
  if (idx >= 0) {
    console.log('Found ternary near:', code.substring(idx - 50, idx + 80).replace(/\n/g, '\n'));
  }
  
  const findings = astAnalyzeCode(code, 'test.java');
  console.log('\nFindings for CWE-22-java-61 (SAFE):');
  for (const f of findings) console.log(' ', f.cweId, '-', f.message.substring(0, 60));
  
  // Also check the Python OWASP file
  const pyCode = fs.readFileSync(
    'C:/Users/drozh/asc-main-dataset/dataset/normalized/CWE-22/python/CWE-22-python-61.py', 'utf-8'
  );
  const pyFindings = astAnalyzeCode(pyCode, 'test.py');
  console.log('\nFindings for CWE-22-python-61 (SAFE):');
  for (const f of pyFindings) console.log(' ', f.cweId, '-', f.message.substring(0, 60));
}
main().catch(console.error);
