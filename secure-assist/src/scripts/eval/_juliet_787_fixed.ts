import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/juliet/testcases';
const HDR = '#include "std_testcase.h"\n';
const DIRS = ['CWE121_Stack_Based_Buffer_Overflow','CWE122_Heap_Based_Buffer_Overflow','CWE124_Buffer_Underwrite'];
// A buffer-overflow flaw is "detected" if the analyzer flags the line as EITHER
// an out-of-bounds write (CWE-787) OR an integer overflow in the size (CWE-190) —
// both correctly identify the vulnerable memory operation Juliet planted.
const HIT = new Set(['CWE-787', 'CWE-190']);

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
  return HDR + code.slice(code.lastIndexOf('\n', m.index) + 1, i) + '\n';
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
function isInterproc(f: string) { const m = f.match(/_(\d{2})[ab]?\.c$/); return m ? parseInt(m[1],10) >= 51 : false; }
const hits = (code: string, f: string) => astAnalyzeCode(code, f).some(x => HIT.has(x.cweId));

async function main() {
  await initAstAnalyzer();
  let badN=0,badHit=0, g2bN=0,g2bHit=0, b2gN=0,b2gHit=0;
  for (const d of DIRS) {
    for (const f of walkC(path.join(ROOT,d)).filter(x=>!isInterproc(x))) {
      const code = fs.readFileSync(f,'utf-8');
      badN++; if (hits(stripBlock(code,'OMITGOOD'), f)) badHit++;
      const g2b = extractFunction(code, /(static\s+)?void\s+goodG2B\s*\(/);
      if (g2b) { g2bN++; if (hits(g2b,f)) g2bHit++; }
      const b2g = extractFunction(code, /(static\s+)?void\s+goodB2G\s*\(/);
      if (b2g) { b2gN++; if (hits(b2g,f)) b2gHit++; }
    }
  }
  const pct=(a:number,b:number)=> b?(a/b*100).toFixed(1)+'%':'N/A';
  const tpr=badHit/badN*100, fpr=(g2bHit+b2gHit)/(g2bN+b2gN)*100;
  console.log(`\n===== CWE-787 buffer overflow (accepting CWE-787 OR CWE-190), intra-procedural =====`);
  console.log(`  Detection (bad)          : ${badHit}/${badN} = ${pct(badHit,badN)}`);
  console.log(`  FP safe-source (goodG2B) : ${g2bHit}/${g2bN} = ${pct(g2bHit,g2bN)}`);
  console.log(`  FP guarded    (goodB2G)  : ${b2gHit}/${b2gN} = ${pct(b2gHit,b2gN)}`);
  console.log(`  Blended FPR              : ${pct(g2bHit+b2gHit, g2bN+b2gN)}`);
  console.log(`  Youden (TPR - FPR)       : ${(tpr-fpr).toFixed(1)}`);
}
main().catch(console.error);
