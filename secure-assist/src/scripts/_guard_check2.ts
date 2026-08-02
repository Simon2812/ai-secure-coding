import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

const FIXED = 'C:/Users/משתמש/Desktop/test/scan-demo/backend/FileService.java';

async function main() {
  await initAstAnalyzer();
  const fixed = fs.readFileSync(FIXED, 'utf-8');

  // A guard that throws but whose pattern permits everything — including "../".
  // The code is still vulnerable, so this should ideally still be flagged.
  const uselessRegex = fixed.replace('"[a-zA-Z0-9._-]+"', '".*"');
  console.log('guard with a permissive regex ".*" (still vulnerable):');
  console.log(' ', astAnalyzeCode(uselessRegex, FIXED).map(f => `${f.cweId}@L${f.line}`).join(', ') || '(none — analyzer suppresses)');
}
main().catch(console.error);
