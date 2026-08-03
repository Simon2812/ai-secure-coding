import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/juliet/testcases';
const HDR = '#include "std_testcase.h"\n';
const DIRS = [
  'CWE121_Stack_Based_Buffer_Overflow',
  'CWE122_Heap_Based_Buffer_Overflow',
  'CWE124_Buffer_Underwrite',
];
const CWE = 'CWE-787';

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
function isInterproc(file: string): boolean {
  const m = file.match(/_(\d{2})[ab]?\.c$/);
  return m ? parseInt(m[1], 10) >= 51 : false;
}

async function main() {
  await initAstAnalyzer();
  let gBadN=0,gBadHit=0, gG2bN=0,gG2bHit=0, gB2gN=0,gB2gHit=0;

  for (const d of DIRS) {
    const all = walkC(path.join(ROOT, d));
    const files = all.filter(f => !isInterproc(f));
    let badN=0,badHit=0, g2bN=0,g2bHit=0, b2gN=0,b2gHit=0;
    for (const f of files) {
      const code = fs.readFileSync(f, 'utf-8');
      const bad = stripBlock(code, 'OMITGOOD');
      badN++; if (astAnalyzeCode(bad, f).some(x => x.cweId === CWE)) badHit++;
      const g2b = extractFunction(code, /(static\s+)?void\s+goodG2B\s*\(/);
      if (g2b) { g2bN++; if (astAnalyzeCode(g2b, f).some(x => x.cweId === CWE)) g2bHit++; }
      const b2g = extractFunction(code, /(static\s+)?void\s+goodB2G\s*\(/);
      if (b2g) { b2gN++; if (astAnalyzeCode(b2g, f).some(x => x.cweId === CWE)) b2gHit++; }
    }
    const pct=(a:number,b:number)=> b?(a/b*100).toFixed(1)+'%':'N/A';
    console.log(`\n${d}  (${files.length} intra-proc of ${all.length})`);
    console.log(`  Detection: ${pct(badHit,badN)}   FP g2b: ${pct(g2bHit,g2bN)}   FP b2g: ${pct(b2gHit,b2gN)}`);
    gBadN+=badN; gBadHit+=badHit; gG2bN+=g2bN; gG2bHit+=g2bHit; gB2gN+=b2gN; gB2gHit+=b2gHit;
  }

  const pct=(a:number,b:number)=> b?(a/b*100).toFixed(1)+'%':'N/A';
  const tpr=gBadHit/gBadN*100, fpr=(gG2bHit+gB2gHit)/(gG2bN+gB2gN)*100;
  console.log(`\n===== CWE-787 (combined, intra-procedural) =====`);
  console.log(`  Detection (bad)          : ${gBadHit}/${gBadN} = ${pct(gBadHit,gBadN)}`);
  console.log(`  FP safe-source (goodG2B) : ${pct(gG2bHit,gG2bN)}`);
  console.log(`  FP guarded    (goodB2G)  : ${pct(gB2gHit,gB2gN)}`);
  console.log(`  Blended FPR              : ${pct(gG2bHit+gB2gHit, gG2bN+gB2gN)}`);
  console.log(`  Youden (TPR - FPR)       : ${(tpr-fpr).toFixed(1)}`);
}
main().catch(console.error);
