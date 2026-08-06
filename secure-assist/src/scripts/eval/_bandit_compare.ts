import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';
import { execSync } from 'child_process';

const BANDIT = process.env.BANDIT_PATH ||
  `${process.env.USERPROFILE}\\AppData\\Roaming\\Python\\Python314\\Scripts\\bandit.exe`;

// Bandit test IDs → CWE
const BANDIT_CWE: Record<string, string[]> = {
  B105: ['CWE-259', 'CWE-321'],  // hardcoded_password_string
  B106: ['CWE-259', 'CWE-321'],  // hardcoded_password_funcarg
  B107: ['CWE-259', 'CWE-321'],  // hardcoded_password_default
  B303: ['CWE-328'],              // md5/sha1 used
  B324: ['CWE-328'],              // hashlib weak hash
  B304: ['CWE-327'],              // ciphers_no_padding
  B305: ['CWE-327'],              // cipher_modes
  B412: ['CWE-327'],              // weak cipher import
  B413: ['CWE-327'],              // pycrypto weak
  B608: ['CWE-89'],               // hardcoded_sql_expressions
  B601: ['CWE-78'],               // paramiko
  B602: ['CWE-78'],               // subprocess shell=True
  B603: ['CWE-78'],               // subprocess no shell
  B604: ['CWE-78'],               // shell=True other
  B605: ['CWE-78'],               // start_process_with_shell
  B606: ['CWE-78'],               // start_process_no_shell
  B607: ['CWE-78'],               // start_process_partial_path
};

const FILES: { path: string; cwe: string; expect: 'VULN' | 'SAFE'; source: string }[] = [
  // CWE-22
  { path: 'C:/temp/cwe22-fresh/python/vuln_zip_slip.py',       cwe: 'CWE-22',  expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe22-fresh/python/safe_realpath_check.py', cwe: 'CWE-22',  expect: 'SAFE', source: 'realistic' },
  // CWE-78
  { path: 'C:/temp/cwe78-fresh/python/vuln_os_system.py',      cwe: 'CWE-78',  expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_popen_concat.py',   cwe: 'CWE-78',  expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe78-fresh/python/safe_subprocess_list.py',cwe: 'CWE-78',  expect: 'SAFE', source: 'realistic' },
  // CWE-89
  { path: 'C:/temp/cwe89-real/python/hackable_main.py',           cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/flask_sqlinjection_db.py',   cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/vulnerable_api_sqli.py',     cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/django_login_views.py',      cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/django_login_safe.py',       cwe: 'CWE-89', expect: 'SAFE', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/vulnerable_api_sqli_safe.py',cwe: 'CWE-89', expect: 'SAFE', source: 'real' },
  // CWE-259
  { path: 'C:/temp/cwe259-fresh/python/vuln_db_conn.py',      cwe: 'CWE-259', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe259-fresh/python/safe_env_password.py', cwe: 'CWE-259', expect: 'SAFE', source: 'realistic' },
  // CWE-321
  { path: 'C:/temp/real-world-50/cwe321/flask_jwt_simple.py', cwe: 'CWE-321', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe321-fresh/python/vuln_aes_literal.py',  cwe: 'CWE-321', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe321-fresh/python/safe_env_key.py',      cwe: 'CWE-321', expect: 'SAFE', source: 'realistic' },
  // CWE-327
  { path: 'C:/temp/fresh50/python/vuln_weak_des.py',          cwe: 'CWE-327', expect: 'VULN', source: 'realistic' },
  // CWE-328
  { path: 'C:/temp/fresh50/python/vuln_weak_md5.py',          cwe: 'CWE-328', expect: 'VULN', source: 'realistic' },
];

function runBandit(filePath: string): Set<string> {
  const cwes = new Set<string>();
  try {
    const out = execSync(
      `"${BANDIT}" -f json -q "${filePath.replace(/\//g, '\\')}"`,
      { encoding: 'utf-8', stdio: ['pipe', 'pipe', 'pipe'] }
    );
    const parsed = JSON.parse(out);
    for (const result of parsed.results ?? []) {
      const testId: string = result.test_id;
      const mapped = BANDIT_CWE[testId];
      if (mapped) mapped.forEach(c => cwes.add(c));
    }
  } catch (e: any) {
    // bandit exits 1 when it finds issues — output is still in stdout
    try {
      const out = e.stdout as string;
      if (out) {
        const parsed = JSON.parse(out);
        for (const result of parsed.results ?? []) {
          const testId: string = result.test_id;
          const mapped = BANDIT_CWE[testId];
          if (mapped) mapped.forEach(c => cwes.add(c));
        }
      }
    } catch { /* ignore */ }
  }
  return cwes;
}

interface Stats { tp: number; fn: number; fp: number; tn: number }

function bucket(stats: Record<string, Stats>, cwe: string, expectVuln: boolean, hit: boolean) {
  if (!stats[cwe]) stats[cwe] = { tp: 0, fn: 0, fp: 0, tn: 0 };
  if (expectVuln && hit)       stats[cwe].tp++;
  else if (expectVuln && !hit) stats[cwe].fn++;
  else if (!expectVuln && hit) stats[cwe].fp++;
  else                         stats[cwe].tn++;
}

function pct(n: number, d: number) { return d > 0 ? (n / d * 100).toFixed(0) + '%' : 'N/A'; }

async function main() {
  await initAstAnalyzer();

  const ourStats:    Record<string, Stats> = {};
  const banditStats: Record<string, Stats> = {};

  console.log(`\n${'File'.padEnd(40)} CWE      Exp   Ours      Bandit`);
  console.log('─'.repeat(80));

  for (const { path: fp, cwe, expect } of FILES) {
    const code = fs.readFileSync(fp, 'utf-8');

    // Our analyzer
    const ourFindings = astAnalyzeCode(code, fp);
    const ourHit = ourFindings.some(f => f.cweId === cwe);

    // Bandit
    const banditCwes = runBandit(fp);
    const banditHit = banditCwes.has(cwe);

    const expectVuln = expect === 'VULN';
    bucket(ourStats,    cwe, expectVuln, ourHit);
    bucket(banditStats, cwe, expectVuln, banditHit);

    const ourV   = expectVuln ? (ourHit    ? '✓ TP' : '✗ FN') : (ourHit    ? '✗ FP' : '✓ TN');
    const banV   = expectVuln ? (banditHit ? '✓ TP' : '✗ FN') : (banditHit ? '✗ FP' : '✓ TN');
    const label  = fp.split('/').slice(-1)[0].padEnd(40);
    console.log(`${label} ${cwe.padEnd(8)} ${expect.padEnd(5)} ${ourV.padEnd(9)} ${banV}`);
  }

  console.log('\n' + '─'.repeat(70));
  console.log(`\n${'CWE'.padEnd(10)} ${'Ours Det%'.padEnd(11)} ${'Ours FP%'.padEnd(10)} ${'Bandit Det%'.padEnd(13)} ${'Bandit FP%'}`);
  console.log('─'.repeat(58));

  const cwes = [...new Set([...Object.keys(ourStats), ...Object.keys(banditStats)])].sort();
  let [oTP,oFN,oFP,oTN,bTP,bFN,bFP,bTN] = [0,0,0,0,0,0,0,0];

  for (const cwe of cwes) {
    const o = ourStats[cwe]    ?? { tp:0,fn:0,fp:0,tn:0 };
    const b = banditStats[cwe] ?? { tp:0,fn:0,fp:0,tn:0 };
    oTP+=o.tp; oFN+=o.fn; oFP+=o.fp; oTN+=o.tn;
    bTP+=b.tp; bFN+=b.fn; bFP+=b.fp; bTN+=b.tn;
    console.log(
      `${cwe.padEnd(10)} ${pct(o.tp,o.tp+o.fn).padEnd(11)} ${pct(o.fp,o.fp+o.tn).padEnd(10)} ${pct(b.tp,b.tp+b.fn).padEnd(13)} ${pct(b.fp,b.fp+b.tn)}`
    );
  }
  console.log('─'.repeat(58));
  console.log(
    `${'TOTAL'.padEnd(10)} ${pct(oTP,oTP+oFN).padEnd(11)} ${pct(oFP,oFP+oTN).padEnd(10)} ${pct(bTP,bTP+bFN).padEnd(13)} ${pct(bFP,bFP+bTN)}`
  );
  console.log(`\nFiles tested: ${FILES.length} Python files`);
}
main().catch(console.error);
