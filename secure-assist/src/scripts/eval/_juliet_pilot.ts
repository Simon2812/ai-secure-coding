import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/juliet/testcases';
const TARGETS: { dir: string; cwe: string }[] = [
  { dir: 'CWE190_Integer_Overflow', cwe: 'CWE-190' },
  { dir: 'CWE416_Use_After_Free',   cwe: 'CWE-416' },
];

// Remove every #ifndef <marker> ... #endif /* <marker> */ block (handles multiple).
function stripBlock(code: string, marker: string): string {
  const lines = code.split('\n');
  const out: string[] = [];
  let skip = false;
  const open = new RegExp(`#ifndef\\s+${marker}\\b`);
  const close = new RegExp(`#endif\\s*/\\*\\s*${marker}\\s*\\*/`);
  for (const line of lines) {
    if (!skip && open.test(line)) { skip = true; continue; }
    if (skip && close.test(line)) { skip = false; continue; }
    if (!skip) out.push(line);
  }
  return out.join('\n');
}

function walkC(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...walkC(full));
    else if (entry.name.endsWith('.c')) results.push(full);
  }
  return results;
}

// flow-variant bucket from filename: _01 baseline, _02.._22 control-flow, _5x/_6x inter-proc/file
function variantBucket(file: string): 'baseline' | 'controlflow' | 'interproc' | 'other' {
  const m = file.match(/_(\d{2})[ab]?\.c$/);
  if (!m) return 'other';
  const n = parseInt(m[1], 10);
  if (n === 1) return 'baseline';
  if (n >= 2 && n <= 22) return 'controlflow';
  if (n >= 51) return 'interproc';
  return 'other';
}

async function main() {
  await initAstAnalyzer();

  for (const { dir, cwe } of TARGETS) {
    const files = walkC(path.join(ROOT, dir));
    let tp=0, fn=0, fp=0, tn=0;
    const buckets: Record<string, {tp:number;fn:number}> = {};

    for (const f of files) {
      const code = fs.readFileSync(f, 'utf-8');
      const badVariant  = stripBlock(code, 'OMITGOOD'); // only bad code remains
      const goodVariant = stripBlock(code, 'OMITBAD');  // only good code remains

      const badHit  = astAnalyzeCode(badVariant,  f).some(x => x.cweId === cwe);
      const goodHit = astAnalyzeCode(goodVariant, f).some(x => x.cweId === cwe);

      if (badHit) tp++; else fn++;      // bad variant SHOULD be flagged
      if (goodHit) fp++; else tn++;     // good variant should NOT be flagged

      const b = variantBucket(f);
      if (!buckets[b]) buckets[b] = { tp:0, fn:0 };
      if (badHit) buckets[b].tp++; else buckets[b].fn++;
    }

    const tpr = tp+fn ? tp/(tp+fn)*100 : 0;
    const fpr = fp+tn ? fp/(fp+tn)*100 : 0;
    console.log(`\n===== ${cwe}  (${files.length} files) =====`);
    console.log(`Bad  variants: TP=${tp}  FN=${fn}   Detection (TPR) = ${tpr.toFixed(1)}%`);
    console.log(`Good variants: FP=${fp}  TN=${tn}   False-positive (FPR) = ${fpr.toFixed(1)}%`);
    console.log(`Youden score (TPR - FPR) = ${(tpr - fpr).toFixed(1)}`);
    console.log(`Detection by flow variant:`);
    for (const b of ['baseline','controlflow','interproc','other']) {
      if (!buckets[b]) continue;
      const s = buckets[b];
      const d = s.tp+s.fn ? (s.tp/(s.tp+s.fn)*100).toFixed(0) : 'N/A';
      console.log(`   ${b.padEnd(12)} ${String(s.tp+s.fn).padStart(5)} cases   detection ${d}%`);
    }
  }
}
main().catch(console.error);
