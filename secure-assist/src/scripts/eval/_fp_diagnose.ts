import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

const ROOT = 'C:/temp/owasp-benchmark';
const CSV  = `${ROOT}/expectedresults-1.2.csv`;
const CODE = `${ROOT}/src/main/java/org/owasp/benchmark/testcode`;
const CAT_CWE: Record<string, string> = { sqli: 'CWE-89', cmdi: 'CWE-78', pathtraver: 'CWE-22' };

async function main() {
  await initAstAnalyzer();
  const fps: Record<string, string[]> = { sqli: [], cmdi: [], pathtraver: [] };

  for (const line of fs.readFileSync(CSV, 'utf-8').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const [test, cat, real] = line.split(',').map(s => s.trim());
    if (!CAT_CWE[cat] || real !== 'false') continue;      // only SAFE cases
    const path = `${CODE}/${test}.java`;
    const code = fs.readFileSync(path, 'utf-8');
    const hit = astAnalyzeCode(code, path).some(f => f.cweId === CAT_CWE[cat]);
    if (hit) fps[cat].push(test);                          // fired on a SAFE case = FP
  }

  for (const cat of Object.keys(fps)) {
    console.log(`\n${cat}: ${fps[cat].length} false positives`);
    console.log('  first 3:', fps[cat].slice(0, 3).join(', '));
  }
}
main().catch(console.error);
