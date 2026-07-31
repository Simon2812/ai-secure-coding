import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

// source: "real" = pulled verbatim/near-verbatim from a real open-source repo or CVE advisory
//         "realistic" = authored earlier this session, modeled on real-world patterns, not literally scraped
const FILES: { path: string; cwe: string; expect: 'VULN' | 'SAFE'; source: 'real' | 'realistic' }[] = [
  // ── CWE-22 Path Traversal ──────────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe22/ProfileUploadBase.java', cwe: 'CWE-22', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/real-world-50/cwe22/ProfileUploadFix.java',  cwe: 'CWE-22', expect: 'SAFE', source: 'real' },
  { path: 'C:/temp/cwe22-fresh/python/vuln_zip_slip.py',        cwe: 'CWE-22', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe22-fresh/python/safe_realpath_check.py',  cwe: 'CWE-22', expect: 'SAFE', source: 'realistic' },
  { path: 'C:/temp/cwe22-fresh/java/SafeFileName.java',         cwe: 'CWE-22', expect: 'SAFE', source: 'realistic' },
  // ── CWE-78 Command Injection ───────────────────────────────────────────
  { path: 'C:/temp/cwe78-fresh/python/vuln_os_system.py',       cwe: 'CWE-78', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_popen_concat.py',    cwe: 'CWE-78', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe78-fresh/java/VulnRuntimeExec.java',      cwe: 'CWE-78', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe78-fresh/python/safe_subprocess_list.py', cwe: 'CWE-78', expect: 'SAFE', source: 'realistic' },
  { path: 'C:/temp/cwe78-fresh/java/SafeAllowlistCmd.java',     cwe: 'CWE-78', expect: 'SAFE', source: 'realistic' },
  // ── CWE-89 SQL Injection (genuinely real, fetched earlier) ─────────────
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson5a.java',     cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson5b.java',     cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson8.java',      cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/hackable_main.py',            cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/flask_sqlinjection_db.py',    cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/vulnerable_api_sqli.py',      cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/django_login_views.py',       cwe: 'CWE-89', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/django_login_safe.py',        cwe: 'CWE-89', expect: 'SAFE', source: 'real' },
  { path: 'C:/temp/cwe89-real/python/vulnerable_api_sqli_safe.py', cwe: 'CWE-89', expect: 'SAFE', source: 'real' },
  // ── CWE-190 Integer Overflow ────────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe190/integer_overflow_read.c', cwe: 'CWE-190', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/fresh50/c/vuln_int_overflow.c',                 cwe: 'CWE-190', expect: 'VULN', source: 'realistic' },
  // ── CWE-259 Hardcoded Password ──────────────────────────────────────────
  { path: 'C:/temp/cwe259-fresh/python/vuln_db_conn.py',        cwe: 'CWE-259', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe259-fresh/java/VulnJdbcPassword.java',    cwe: 'CWE-259', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe259-fresh/c/vuln_strcmp_password.c',      cwe: 'CWE-259', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe259-fresh/python/safe_env_password.py',   cwe: 'CWE-259', expect: 'SAFE', source: 'realistic' },
  { path: 'C:/temp/cwe259-fresh/java/SafePropertiesPassword.java', cwe: 'CWE-259', expect: 'SAFE', source: 'realistic' },
  // ── CWE-321 Hardcoded Crypto Key ────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe321/flask_jwt_simple.py',   cwe: 'CWE-321', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/cwe321-fresh/python/vuln_aes_literal.py',    cwe: 'CWE-321', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe321-fresh/java/VulnHardcodedAES.java',    cwe: 'CWE-321', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/cwe321-fresh/python/safe_env_key.py',        cwe: 'CWE-321', expect: 'SAFE', source: 'realistic' },
  { path: 'C:/temp/cwe321-fresh/java/SafeEnvKey.java',          cwe: 'CWE-321', expect: 'SAFE', source: 'realistic' },
  // ── CWE-327 Broken/Weak Cipher ───────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe327/des_noncompliant.java', cwe: 'CWE-327', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/real-world-50/cwe327/aes_gcm_compliant.java',cwe: 'CWE-327', expect: 'SAFE', source: 'real' },
  { path: 'C:/temp/fresh50/python/vuln_weak_des.py',            cwe: 'CWE-327', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/fresh50/java/VulnRC4.java',                  cwe: 'CWE-327', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/fresh50/java/SafeSecureRandom.java',         cwe: 'CWE-327', expect: 'SAFE', source: 'realistic' },
  // ── CWE-328 Weak Hash ────────────────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe328/HashingAssignment.java',       cwe: 'CWE-328', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/real-world-50/cwe328/SecureDefaultsAssignment.java',cwe: 'CWE-328', expect: 'SAFE', source: 'real' },
  { path: 'C:/temp/fresh50/python/vuln_weak_md5.py',            cwe: 'CWE-328', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/fresh50/java/VulnWeakMD5.java',              cwe: 'CWE-328', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/fresh50/java/SafeSha256Hash.java',           cwe: 'CWE-328', expect: 'SAFE', source: 'realistic' },
  // ── CWE-416 Use After Free ───────────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe416/test1.c',               cwe: 'CWE-416', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/real-world-50/cwe416/test2.c',               cwe: 'CWE-416', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/fresh50/c/vuln_use_after_free.c',            cwe: 'CWE-416', expect: 'VULN', source: 'realistic' },
  { path: 'C:/temp/fresh50/c/safe_free_null.c',                 cwe: 'CWE-416', expect: 'SAFE', source: 'realistic' },
  // ── CWE-787 Out-of-bounds Write ──────────────────────────────────────────
  { path: 'C:/temp/real-world-50/cwe787/extractVersionQuad.c',  cwe: 'CWE-787', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/real-world-50/cwe787/rtsp_handshake.c',      cwe: 'CWE-787', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/real-world-50/cwe787/scanf_unbounded.c',     cwe: 'CWE-787', expect: 'VULN', source: 'real' },
  { path: 'C:/temp/fresh50/c/safe_snprintf_bounds.c',           cwe: 'CWE-787', expect: 'SAFE', source: 'realistic' },
];

interface Stats { tp: number; fn: number; fp: number; tn: number }

function bucket(stats: Record<string, Stats>, cwe: string, expectVuln: boolean, hit: boolean) {
  if (!stats[cwe]) stats[cwe] = { tp: 0, fn: 0, fp: 0, tn: 0 };
  if (expectVuln && hit)        stats[cwe].tp++;
  else if (expectVuln && !hit)  stats[cwe].fn++;
  else if (!expectVuln && hit)  stats[cwe].fp++;
  else                          stats[cwe].tn++;
}

async function main() {
  await initAstAnalyzer();
  const stats: Record<string, Stats> = {};
  let realCount = 0, realisticCount = 0;

  console.log(`\n${'File'.padEnd(46)} CWE      Expect  Source     Result`);
  console.log('─'.repeat(95));

  for (const { path: fp, cwe, expect, source } of FILES) {
    if (source === 'real') realCount++; else realisticCount++;
    const code = fs.readFileSync(fp, 'utf-8');
    const findings = astAnalyzeCode(code, fp);
    const hit = findings.some(f => f.cweId === cwe);
    const expectVuln = expect === 'VULN';

    bucket(stats, cwe, expectVuln, hit);

    const verdict = expectVuln
      ? (hit ? '✓ TP' : '✗ FN')
      : (hit ? '✗ FP' : '✓ TN');

    const label = fp.split('/').slice(-2).join('/');
    console.log(`${label.padEnd(46)} ${cwe.padEnd(8)} ${expect.padEnd(7)} ${source.padEnd(10)} ${verdict}`);
  }

  console.log('\n' + '─'.repeat(70));
  console.log(`Total files: ${FILES.length}  (${realCount} real, ${realisticCount} realistic-authored)\n`);
  console.log(`${'CWE'.padEnd(10)}TP   FN   FP   TN   Det%     FP%`);
  console.log('─'.repeat(50));

  let totTP=0, totFN=0, totFP=0, totTN=0;
  for (const cwe of Object.keys(stats).sort()) {
    const s = stats[cwe];
    totTP += s.tp; totFN += s.fn; totFP += s.fp; totTN += s.tn;
    const det = (s.tp + s.fn) > 0 ? (s.tp / (s.tp + s.fn) * 100).toFixed(0) + '%' : 'N/A';
    const fpr = (s.fp + s.tn) > 0 ? (s.fp / (s.fp + s.tn) * 100).toFixed(0) + '%' : 'N/A';
    console.log(`${cwe.padEnd(10)}${String(s.tp).padEnd(5)}${String(s.fn).padEnd(5)}${String(s.fp).padEnd(5)}${String(s.tn).padEnd(5)}${det.padEnd(9)}${fpr}`);
  }
  console.log('─'.repeat(50));
  const totDet = (totTP+totFN) > 0 ? (totTP/(totTP+totFN)*100).toFixed(1)+'%' : 'N/A';
  const totFPR = (totFP+totTN) > 0 ? (totFP/(totFP+totTN)*100).toFixed(1)+'%' : 'N/A';
  console.log(`${'TOTAL'.padEnd(10)}${String(totTP).padEnd(5)}${String(totFN).padEnd(5)}${String(totFP).padEnd(5)}${String(totTN).padEnd(5)}${totDet.padEnd(9)}${totFPR}`);
}
main().catch(console.error);
