import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

// Real-world evaluation set: intentionally-vulnerable apps + real CVE code.
// Ground truth established by reading each file. Multi-CWE files have one entry per CWE.
type E = { file: string; cwe: string; expect: 'VULN' | 'SAFE'; app: string };
const T = 'C:/temp/';
const ENTRIES: E[] = [
  // ── DSVW (Damn Small Vulnerable Web) — one file, several real vulns ──
  { file: 'realworld-set/python/dsvw.py', cwe: 'CWE-89', expect: 'VULN', app: 'DSVW' },
  { file: 'realworld-set/python/dsvw.py', cwe: 'CWE-22', expect: 'VULN', app: 'DSVW' },
  { file: 'realworld-set/python/dsvw.py', cwe: 'CWE-78', expect: 'VULN', app: 'DSVW' },
  // ── WebGoat (real lessons) ──
  { file: 'realworld-set/java/SqlInjectionChallenge.java', cwe: 'CWE-89', expect: 'VULN', app: 'WebGoat' },
  { file: 'realworld-set/java/CipherService.java',         cwe: 'CWE-328', expect: 'SAFE', app: 'WebGoat' },
  { file: 'cwe89-real/java/SqlInjectionLesson5a.java',     cwe: 'CWE-89', expect: 'VULN', app: 'WebGoat' },
  { file: 'cwe89-real/java/SqlInjectionLesson5b.java',     cwe: 'CWE-89', expect: 'VULN', app: 'WebGoat' },
  { file: 'cwe89-real/java/SqlInjectionLesson8.java',      cwe: 'CWE-89', expect: 'VULN', app: 'WebGoat' },
  { file: 'real-world-50/cwe22/ProfileUploadBase.java',    cwe: 'CWE-22', expect: 'VULN', app: 'WebGoat' },
  { file: 'real-world-50/cwe22/ProfileUploadFix.java',     cwe: 'CWE-22', expect: 'SAFE', app: 'WebGoat' },
  { file: 'real-world-50/cwe328/HashingAssignment.java',   cwe: 'CWE-328', expect: 'VULN', app: 'WebGoat' },
  { file: 'real-world-50/cwe328/SecureDefaultsAssignment.java', cwe: 'CWE-328', expect: 'SAFE', app: 'WebGoat' },
  // ── Real Flask/Django vulnerable apps ──
  { file: 'cwe89-real/python/hackable_main.py',            cwe: 'CWE-89', expect: 'VULN', app: 'hackable' },
  { file: 'cwe89-real/python/flask_sqlinjection_db.py',    cwe: 'CWE-89', expect: 'VULN', app: 'flask-sqli' },
  { file: 'cwe89-real/python/vulnerable_api_sqli.py',      cwe: 'CWE-89', expect: 'VULN', app: 'Vulnerable-API' },
  { file: 'cwe89-real/python/vulnerable_api_sqli_safe.py', cwe: 'CWE-89', expect: 'SAFE', app: 'Vulnerable-API' },
  { file: 'cwe89-real/python/django_login_views.py',       cwe: 'CWE-89', expect: 'VULN', app: 'Django-sqli' },
  { file: 'cwe89-real/python/django_login_safe.py',        cwe: 'CWE-89', expect: 'SAFE', app: 'Django-sqli' },
  // ── PyGoat (OWASP) ──
  { file: 'independent-samples/pygoat_views.py',           cwe: 'CWE-89', expect: 'VULN', app: 'PyGoat' },
  { file: 'independent-samples/pygoat_views.py',           cwe: 'CWE-78', expect: 'VULN', app: 'PyGoat' },
  // ── Vulpy ──
  { file: 'independent-samples/vulpy_libuser.py',          cwe: 'CWE-89', expect: 'VULN', app: 'Vulpy' },
  { file: 'independent-samples/vulpy_libposts.py',         cwe: 'CWE-89', expect: 'SAFE', app: 'Vulpy' },
  { file: 'independent-samples/vulpy_mod_user.py',         cwe: 'CWE-89', expect: 'SAFE', app: 'Vulpy(x-file)' },
  { file: 'independent-samples/vulpy_brute.py',            cwe: 'CWE-78', expect: 'SAFE', app: 'Vulpy' },
  // ── Real CVE crypto (CMU CERT) ──
  { file: 'real-world-50/cwe327/des_noncompliant.java',    cwe: 'CWE-327', expect: 'VULN', app: 'CERT' },
  { file: 'real-world-50/cwe327/aes_gcm_compliant.java',   cwe: 'CWE-327', expect: 'SAFE', app: 'CERT' },
  // ── Real crypto-key (flask-jwt-extended) ──
  { file: 'real-world-50/cwe321/flask_jwt_simple.py',      cwe: 'CWE-321', expect: 'VULN', app: 'flask-jwt' },
  // ── Real CVE C code ──
  { file: 'real-world-50/cwe416/test1.c',                  cwe: 'CWE-416', expect: 'VULN', app: 'seeve' },
  { file: 'real-world-50/cwe416/test2.c',                  cwe: 'CWE-416', expect: 'VULN', app: 'seeve' },
  { file: 'real-world-50/cwe787/extractVersionQuad.c',     cwe: 'CWE-787', expect: 'VULN', app: 'moonlight-CVE' },
  { file: 'real-world-50/cwe787/rtsp_handshake.c',         cwe: 'CWE-787', expect: 'VULN', app: 'moonlight-CVE' },
  { file: 'real-world-50/cwe787/scanf_unbounded.c',        cwe: 'CWE-787', expect: 'VULN', app: 'seeve' },
  { file: 'real-world-50/cwe190/integer_overflow_read.c',  cwe: 'CWE-190', expect: 'VULN', app: 'seeve' },
];

interface Stat { tp:number; fn:number; fp:number; tn:number }

async function main() {
  await initAstAnalyzer();
  const stats: Record<string, Stat> = {};
  let missing = 0;

  console.log(`\n${'App'.padEnd(16)}${'File'.padEnd(34)}${'CWE'.padEnd(9)}${'Exp'.padEnd(6)}Result`);
  console.log('─'.repeat(78));

  for (const e of ENTRIES) {
    const path = T + e.file;
    if (!fs.existsSync(path)) { console.log(`MISSING ${e.file}`); missing++; continue; }
    const code = fs.readFileSync(path, 'utf-8');
    const hit = astAnalyzeCode(code, path).some(f => f.cweId === e.cwe);
    const vuln = e.expect === 'VULN';
    if (!stats[e.cwe]) stats[e.cwe] = { tp:0, fn:0, fp:0, tn:0 };
    const s = stats[e.cwe];
    let r: string;
    if (vuln && hit)      { s.tp++; r = '✓ TP'; }
    else if (vuln)        { s.fn++; r = '✗ FN'; }
    else if (hit)         { s.fp++; r = '✗ FP'; }
    else                  { s.tn++; r = '✓ TN'; }
    const fname = e.file.split('/').pop() ?? e.file;
    console.log(`${e.app.padEnd(16)}${fname.slice(0,33).padEnd(34)}${e.cwe.padEnd(9)}${e.expect.padEnd(6)}${r}`);
  }

  console.log('\n' + '─'.repeat(56));
  console.log(`${'CWE'.padEnd(10)}TP   FN   FP   TN   Detection  FP%`);
  console.log('─'.repeat(56));
  let TP=0,FN=0,FP=0,TN=0;
  for (const cwe of Object.keys(stats).sort()) {
    const s = stats[cwe]; TP+=s.tp;FN+=s.fn;FP+=s.fp;TN+=s.tn;
    const det = s.tp+s.fn ? (s.tp/(s.tp+s.fn)*100).toFixed(0)+'%' : 'N/A';
    const fpr = s.fp+s.tn ? (s.fp/(s.fp+s.tn)*100).toFixed(0)+'%' : 'N/A';
    console.log(`${cwe.padEnd(10)}${String(s.tp).padEnd(5)}${String(s.fn).padEnd(5)}${String(s.fp).padEnd(5)}${String(s.tn).padEnd(5)}${det.padEnd(11)}${fpr}`);
  }
  console.log('─'.repeat(56));
  const det = (TP/(TP+FN)*100).toFixed(1)+'%';
  const fpr = FP+TN ? (FP/(FP+TN)*100).toFixed(1)+'%' : 'N/A';
  console.log(`${'TOTAL'.padEnd(10)}${String(TP).padEnd(5)}${String(FN).padEnd(5)}${String(FP).padEnd(5)}${String(TN).padEnd(5)}${det.padEnd(11)}${fpr}`);
  console.log(`\nEntries: ${ENTRIES.length} (${missing} missing).  Distinct files across ${new Set(ENTRIES.map(e=>e.file)).size}.`);
}
main().catch(console.error);
