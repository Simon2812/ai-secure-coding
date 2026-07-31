import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const DIR = 'C:/temp/juliet/testcases/CWE121_Stack_Based_Buffer_Overflow';

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
function isInterproc(file: string): boolean {
  const m = file.match(/_(\d{2})[ab]?\.c$/);
  return m ? parseInt(m[1], 10) >= 51 : false;
}
// sink family from filename token before the flow-variant number
function sinkFamily(file: string): string {
  const base = path.basename(file);
  const m = base.match(/_([a-z]+)_\d{2}[ab]?\.c$/);
  return m ? m[1] : 'other';
}

async function main() {
  await initAstAnalyzer();
  const files = walkC(DIR).filter(f => !isInterproc(f));
  const stats: Record<string, {n:number;hit:number}> = {};
  for (const f of files) {
    const code = fs.readFileSync(f, 'utf-8');
    const bad = stripBlock(code, 'OMITGOOD');
    const hit = astAnalyzeCode(bad, f).some(x => x.cweId === 'CWE-787');
    const fam = sinkFamily(f);
    if (!stats[fam]) stats[fam] = { n:0, hit:0 };
    stats[fam].n++; if (hit) stats[fam].hit++;
  }
  console.log(`CWE-121 detection by sink family (intra-proc, ${files.length} files):\n`);
  const rows = Object.entries(stats).sort((a,b)=>b[1].n-a[1].n);
  for (const [fam, s] of rows) {
    console.log(`  ${fam.padEnd(12)} ${String(s.hit).padStart(4)}/${String(s.n).padEnd(5)} = ${(s.hit/s.n*100).toFixed(0)}%`);
  }
}
main().catch(console.error);
