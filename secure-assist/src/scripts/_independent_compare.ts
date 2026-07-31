import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import { execSync } from 'child_process';

const BANDIT = `${process.env.USERPROFILE}\\AppData\\Roaming\\Python\\Python314\\Scripts\\bandit.exe`;
const DIR = 'C:/temp/independent-samples';

const BANDIT_CWE: Record<string, string> = {
  B608: 'CWE-89',
  B602: 'CWE-78', B603: 'CWE-78', B604: 'CWE-78', B605: 'CWE-78', B606: 'CWE-78', B607: 'CWE-78',
};

// Ground truth established by reading each file BEFORE running any tool.
const CASES: { file: string; cwe: string; expect: 'VULN' | 'SAFE'; note: string }[] = [
  { file: 'pygoat_views.py',   cwe: 'CWE-89', expect: 'VULN', note: '.raw() + concat from request.POST (L158/162)' },
  { file: 'pygoat_views.py',   cwe: 'CWE-78', expect: 'VULN', note: 'Popen(shell=True) from request.POST (L424/430)' },
  { file: 'vulpy_libuser.py',  cwe: 'CWE-89', expect: 'VULN', note: '.format()/% injection (L12/25/53)' },
  { file: 'vulpy_libposts.py', cwe: 'CWE-89', expect: 'SAFE', note: 'parameterized ? — also DESC test' },
  { file: 'vulpy_mod_user.py', cwe: 'CWE-89', expect: 'SAFE', note: 'no local sink — vuln is cross-file only' },
  { file: 'vulpy_brute.py',    cwe: 'CWE-78', expect: 'SAFE', note: 'list-form subprocess, no shell' },
];

function runBandit(filePath: string): Set<string> {
  const cwes = new Set<string>();
  const parse = (out: string) => {
    const parsed = JSON.parse(out);
    for (const r of parsed.results ?? []) {
      const c = BANDIT_CWE[r.test_id];
      if (c) cwes.add(c);
    }
  };
  try {
    parse(execSync(`"${BANDIT}" -f json -q "${filePath.replace(/\//g, '\\')}"`, { encoding: 'utf-8' }));
  } catch (e: any) {
    try { if (e.stdout) parse(e.stdout as string); } catch { /* ignore */ }
  }
  return cwes;
}

async function main() {
  await initAstAnalyzer();

  console.log(`\n${'File'.padEnd(22)} ${'CWE'.padEnd(8)} ${'Truth'.padEnd(6)} ${'Ours'.padEnd(7)} ${'Bandit'.padEnd(7)} Note`);
  console.log('─'.repeat(100));

  let oTP=0,oFN=0,oFP=0,oTN=0, bTP=0,bFN=0,bFP=0,bTN=0;

  for (const { file, cwe, expect, note } of CASES) {
    const code = fs.readFileSync(`${DIR}/${file}`, 'utf-8');
    const ourHit    = astAnalyzeCode(code, file).some(f => f.cweId === cwe);
    const banditHit = runBandit(`${DIR}/${file}`).has(cwe);
    const vuln = expect === 'VULN';

    if (vuln &&  ourHit)    oTP++; else if (vuln && !ourHit)    oFN++;
    else if (!vuln && ourHit)    oFP++; else oTN++;
    if (vuln &&  banditHit) bTP++; else if (vuln && !banditHit) bFN++;
    else if (!vuln && banditHit) bFP++; else bTN++;

    const ov = vuln ? (ourHit    ? '✓ TP' : '✗ FN') : (ourHit    ? '✗ FP' : '✓ TN');
    const bv = vuln ? (banditHit ? '✓ TP' : '✗ FN') : (banditHit ? '✗ FP' : '✓ TN');
    console.log(`${file.padEnd(22)} ${cwe.padEnd(8)} ${expect.padEnd(6)} ${ov.padEnd(7)} ${bv.padEnd(7)} ${note}`);
  }

  const det = (tp: number, fn: number) => (tp+fn) ? (tp/(tp+fn)*100).toFixed(0)+'%' : 'N/A';
  const fpr = (fp: number, tn: number) => (fp+tn) ? (fp/(fp+tn)*100).toFixed(0)+'%' : 'N/A';

  console.log('\n' + '─'.repeat(60));
  console.log(`${''.padEnd(12)} ${'TP'.padEnd(4)}${'FN'.padEnd(4)}${'FP'.padEnd(4)}${'TN'.padEnd(4)} ${'Det%'.padEnd(7)}FP%`);
  console.log('─'.repeat(60));
  console.log(`${'Ours'.padEnd(12)} ${String(oTP).padEnd(4)}${String(oFN).padEnd(4)}${String(oFP).padEnd(4)}${String(oTN).padEnd(4)} ${det(oTP,oFN).padEnd(7)}${fpr(oFP,oTN)}`);
  console.log(`${'Bandit'.padEnd(12)} ${String(bTP).padEnd(4)}${String(bFN).padEnd(4)}${String(bFP).padEnd(4)}${String(bTN).padEnd(4)} ${det(bTP,bFN).padEnd(7)}${fpr(bFP,bTN)}`);
  console.log('─'.repeat(60));
  console.log('\nSeparately — vulpy_db.py: %-into-SQL with hardcoded constants (bad practice, not exploitable):');
  const dbCode = fs.readFileSync(`${DIR}/vulpy_db.py`, 'utf-8');
  console.log(`  Ours fires CWE-89?   ${astAnalyzeCode(dbCode,'vulpy_db.py').some(f=>f.cweId==='CWE-89')}`);
  console.log(`  Bandit fires CWE-89? ${runBandit(`${DIR}/vulpy_db.py`).has('CWE-89')}`);
}
main().catch(console.error);
