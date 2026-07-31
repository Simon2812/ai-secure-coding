import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

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

async function main() {
  await initAstAnalyzer();
  // all memcpy/memmove bad files across the 3 buffer CWEs
  const dirs = ['CWE121_Stack_Based_Buffer_Overflow','CWE122_Heap_Based_Buffer_Overflow','CWE124_Buffer_Underwrite'];
  let n=0, fire787=0, fire190=0, fireAny=0, none=0;
  for (const d of dirs) {
    for (const f of walkC('C:/temp/juliet/testcases/'+d).filter(x=>!isInterproc(x) && /_(memcpy|memmove)_/.test(x))) {
      const bad = stripBlock(fs.readFileSync(f,'utf-8'), 'OMITGOOD');
      const ids = new Set(astAnalyzeCode(bad, f).map(x=>x.cweId));
      n++;
      if (ids.has('CWE-787')) fire787++;
      if (ids.has('CWE-190')) fire190++;
      if (ids.size>0) fireAny++; else none++;
    }
  }
  console.log(`memcpy/memmove bad files (intra-proc): ${n}`);
  console.log(`  fired CWE-787: ${fire787}`);
  console.log(`  fired CWE-190: ${fire190}   <-- detected but labeled as overflow, not OOB-write`);
  console.log(`  fired anything: ${fireAny}`);
  console.log(`  detected NOTHING: ${none}`);
}
main().catch(console.error);
