import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

const ROOT = 'C:/temp/owasp-benchmark';
const CSV  = `${ROOT}/expectedresults-1.2.csv`;
const CODE = `${ROOT}/src/main/java/org/owasp/benchmark/testcode`;

// OWASP category → the CWE id our analyzer emits
const CAT_CWE: Record<string, string> = {
  sqli: 'CWE-89',
  pathtraver: 'CWE-22',
  cmdi: 'CWE-78',
  crypto: 'CWE-327',
  hash: 'CWE-328',
};

interface Row { test: string; cat: string; real: boolean; cwe: string }

function parseCsv(): Row[] {
  const rows: Row[] = [];
  for (const line of fs.readFileSync(CSV, 'utf-8').split(/\r?\n/)) {
    if (!line || line.startsWith('#')) continue;
    const [test, cat, real, cwe] = line.split(',').map(s => s.trim());
    if (!test || !cat) continue;
    rows.push({ test, cat, real: real === 'true', cwe });
  }
  return rows;
}

interface Stat { tp: number; fn: number; fp: number; tn: number }

async function main() {
  await initAstAnalyzer();
  const rows = parseCsv().filter(r => CAT_CWE[r.cat]);

  const stats: Record<string, Stat> = {};
  let processed = 0, missing = 0;

  for (const r of rows) {
    const expectedCwe = CAT_CWE[r.cat];
    const path = `${CODE}/${r.test}.java`;
    if (!fs.existsSync(path)) { missing++; continue; }
    const code = fs.readFileSync(path, 'utf-8');

    let hit = false;
    try {
      hit = astAnalyzeCode(code, path).some(f => f.cweId === expectedCwe);
    } catch { hit = false; }

    if (!stats[r.cat]) stats[r.cat] = { tp: 0, fn: 0, fp: 0, tn: 0 };
    const s = stats[r.cat];
    if (r.real &&  hit) s.tp++;
    else if (r.real && !hit) s.fn++;
    else if (!r.real && hit) s.fp++;
    else s.tn++;
    processed++;
  }

  console.log(`\nProcessed ${processed} cases (${missing} missing files)\n`);
  console.log(`${'Category'.padEnd(12)}${'CWE'.padEnd(9)}${'TP'.padEnd(5)}${'FN'.padEnd(5)}${'FP'.padEnd(5)}${'TN'.padEnd(5)}${'TPR'.padEnd(7)}${'FPR'.padEnd(7)}Score`);
  console.log('─'.repeat(66));

  let TP=0,FN=0,FP=0,TN=0;
  let youdenSum = 0, catCount = 0;
  for (const cat of Object.keys(CAT_CWE).filter(c => stats[c])) {
    const s = stats[cat];
    TP+=s.tp; FN+=s.fn; FP+=s.fp; TN+=s.tn;
    const tpr = s.tp+s.fn ? s.tp/(s.tp+s.fn) : 0;
    const fpr = s.fp+s.tn ? s.fp/(s.fp+s.tn) : 0;
    const youden = tpr - fpr;
    youdenSum += youden; catCount++;
    console.log(
      `${cat.padEnd(12)}${CAT_CWE[cat].padEnd(9)}${String(s.tp).padEnd(5)}${String(s.fn).padEnd(5)}${String(s.fp).padEnd(5)}${String(s.tn).padEnd(5)}` +
      `${(tpr*100).toFixed(0).padEnd(1)}%`.padEnd(7) +
      `${(fpr*100).toFixed(0)}%`.padEnd(7) +
      `${(youden*100).toFixed(0)}`
    );
  }
  console.log('─'.repeat(66));
  const tpr = TP+FN ? TP/(TP+FN) : 0;
  const fpr = FP+TN ? FP/(FP+TN) : 0;
  console.log(
    `${'OVERALL'.padEnd(21)}${String(TP).padEnd(5)}${String(FN).padEnd(5)}${String(FP).padEnd(5)}${String(TN).padEnd(5)}` +
    `${(tpr*100).toFixed(0)}%`.padEnd(7) + `${(fpr*100).toFixed(0)}%`.padEnd(7) + `${((tpr-fpr)*100).toFixed(0)}`
  );
  console.log(`\nOWASP Benchmark score (avg per-category Youden, TPR−FPR): ${(youdenSum/catCount*100).toFixed(1)}`);
  console.log('(Score is the official OWASP metric — 0 = random guessing, 100 = perfect)');
}
main().catch(console.error);
