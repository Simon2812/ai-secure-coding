import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/juliet/testcases';
const HDR = '#include "std_testcase.h"\n';

function stripBlock(code: string, marker: string): string {
  const lines = code.split('\n'); const out: string[] = []; let skip = false;
  const open = new RegExp(`#ifndef\\s+${marker}\\b`), close = new RegExp(`#endif\\s*/\\*\\s*${marker}\\s*\\*/`);
  for (const l of lines) {
    if (!skip && open.test(l)) { skip = true; continue; }
    if (skip && close.test(l)) { skip = false; continue; }
    if (!skip) out.push(l);
  }
  return out.join('\n');
}

// Extract a single function body by a signature regex, via brace matching.
function extractFunction(code: string, sigRe: RegExp): string | null {
  const m = code.match(sigRe);
  if (!m || m.index === undefined) return null;
  const braceStart = code.indexOf('{', m.index);
  if (braceStart < 0) return null;
  let depth = 0, i = braceStart;
  for (; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') { depth--; if (depth === 0) { i++; break; } }
  }
  const sigLineStart = code.lastIndexOf('\n', m.index) + 1;
  return HDR + code.slice(sigLineStart, i) + '\n';
}

function walkC(dir: string): string[] {
  const r: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) r.push(...walkC(full));
    else if (e.name.endsWith('.c')) r.push(full);
  }
  return r;
}

async function main() {
  await initAstAnalyzer();
  for (const [dir, cwe] of [['CWE190_Integer_Overflow','CWE-190'],['CWE416_Use_After_Free','CWE-416']] as const) {
    const files = walkC(path.join(ROOT, dir));
    let badN=0, badHit=0;                 // detection
    let g2bN=0, g2bHit=0;                 // FP on constant/safe-source good
    let b2gN=0, b2gHit=0;                 // FP on guarded good

    for (const f of files) {
      const code = fs.readFileSync(f, 'utf-8');
      const bad = stripBlock(code, 'OMITGOOD');
      if (astAnalyzeCode(bad, f).length >= 0) { // always true; just structure
        badN++;
        if (astAnalyzeCode(bad, f).some(x => x.cweId === cwe)) badHit++;
      }
      const g2b = extractFunction(code, /(static\s+)?void\s+goodG2B\s*\(/);
      if (g2b) { g2bN++; if (astAnalyzeCode(g2b, f).some(x => x.cweId === cwe)) g2bHit++; }
      const b2g = extractFunction(code, /(static\s+)?void\s+goodB2G\s*\(/);
      if (b2g) { b2gN++; if (astAnalyzeCode(b2g, f).some(x => x.cweId === cwe)) b2gHit++; }
    }

    const pct = (a:number,b:number)=> b? (a/b*100).toFixed(1)+'%' : 'N/A';
    console.log(`\n===== ${cwe} (${files.length} files) — functions tested SEPARATELY =====`);
    console.log(`  bad()     : ${badHit}/${badN} fired   → Detection (TPR) = ${pct(badHit,badN)}`);
    console.log(`  goodG2B() : ${g2bHit}/${g2bN} fired   → FP on safe-source good = ${pct(g2bHit,g2bN)}`);
    console.log(`  goodB2G() : ${b2gHit}/${b2gN} fired   → FP on guarded good     = ${pct(b2gHit,b2gN)}`);
  }
}
main().catch(console.error);
