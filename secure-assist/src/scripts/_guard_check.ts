import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

const FIXED = 'C:/Users/משתמש/Desktop/test/scan-demo/backend/FileService.java';

async function main() {
  await initAstAnalyzer();

  const fixed = fs.readFileSync(FIXED, 'utf-8');
  console.log('=== current file (with the matches() guard) ===');
  console.log(' ', astAnalyzeCode(fixed, FIXED).map(f => `${f.cweId}@L${f.line}`).join(', ') || '(none)');

  // Same file with the guard removed — isolates whether the guard is the reason.
  const withoutGuard = fixed.replace(
    /if \(!name\.matches[\s\S]*?\}\n/,
    ''
  );
  console.log('\n=== same file, guard deleted ===');
  console.log(' ', astAnalyzeCode(withoutGuard, FIXED).map(f => `${f.cweId}@L${f.line}`).join(', ') || '(none)');

  // A guard that does NOT actually protect (no throw) — should still be flagged.
  const weakGuard = fixed.replace(
    'throw new IllegalArgumentException("Invalid filename");',
    'System.out.println("odd name");'
  );
  console.log('\n=== guard present but no throw (does not protect) ===');
  console.log(' ', astAnalyzeCode(weakGuard, FIXED).map(f => `${f.cweId}@L${f.line}`).join(', ') || '(none)');
}
main().catch(console.error);
