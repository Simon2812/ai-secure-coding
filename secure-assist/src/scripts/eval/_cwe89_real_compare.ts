import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import { findSqlInjection } from '../../analyzer/rules/sqlInjection';
import { detectLanguage } from '../../analyzer/utils';
import * as fs from 'fs';

function regexCwe89(code: string, filePath: string) {
  return findSqlInjection({ code, filePath, language: detectLanguage(filePath) });
}

const FILES: { path: string; expect: 'VULN' | 'SAFE'; note: string }[] = [
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson5a.java', expect: 'VULN', note: 'WebGoat — concat in WHERE clause' },
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson5b.java', expect: 'VULN', note: 'WebGoat — mixed PreparedStatement + concat' },
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson8.java',  expect: 'VULN', note: 'WebGoat — dual sink (query + log insert)' },
  { path: 'C:/temp/cwe89-real/java/SqlInjectionLesson9.java',  expect: 'VULN', note: 'WebGoat — calls Lesson8.log + has safe sibling fn' },
  { path: 'C:/temp/cwe89-real/python/hackable_main.py',        expect: 'VULN', note: 'hackable — % format + safe POST in same file' },
  { path: 'C:/temp/cwe89-real/python/flask_sqlinjection_db.py',expect: 'VULN', note: 'flask-sqlinjection-vulnerable — multiline f-string' },
  { path: 'C:/temp/cwe89-real/python/vulnerable_api_sqli.py',  expect: 'VULN', note: 'Vulnerable-API — generic dict param, not request.*' },
  { path: 'C:/temp/cwe89-real/python/django_login_views.py',   expect: 'VULN', note: 'Django — request.POST + .format() raw()' },
  { path: 'C:/temp/cwe89-real/python/django_login_safe.py',    expect: 'SAFE', note: 'Django ORM filter() — parameterized' },
  { path: 'C:/temp/cwe89-real/python/vulnerable_api_sqli_safe.py', expect: 'SAFE', note: 'parameterized ? placeholder' },
];

function verdict(hit: boolean, expect: 'VULN' | 'SAFE') {
  if (expect === 'VULN') return hit ? '✓ TP' : '✗ FN';
  return hit ? '✗ FP' : '✓ TN';
}

async function main() {
  await initAstAnalyzer();
  let rTP=0,rFN=0,rFP=0,rTN=0,aTP=0,aFN=0,aFP=0,aTN=0;

  console.log(`\n${'File'.padEnd(34)} Expect  Regex   AST    Note`);
  console.log('─'.repeat(110));

  for (const { path: fp, expect, note } of FILES) {
    const code = fs.readFileSync(fp, 'utf-8');
    const label = fp.split('/').slice(-2).join('/');

    const rHit = regexCwe89(code, fp).length > 0;
    const aHit = astAnalyzeCode(code, fp).some(f => f.cweId === 'CWE-89');

    const rv = verdict(rHit, expect);
    const av = verdict(aHit, expect);

    if (expect === 'VULN') { rHit ? rTP++ : rFN++; aHit ? aTP++ : aFN++; }
    else                   { rHit ? rFP++ : rTN++; aHit ? aFP++ : aTN++; }

    const flag = rv !== av ? ' ◄' : '';
    console.log(`${label.padEnd(34)} ${expect.padEnd(7)} ${rv.padEnd(7)} ${av}${flag}  ${note}`);
  }

  const fmt = (a:number,b:number) => b > 0 ? (a/b*100).toFixed(0)+'%' : 'N/A';
  console.log('\n' + '─'.repeat(60));
  console.log(`${''.padEnd(14)}Regex    AST`);
  console.log(`${'TP'.padEnd(14)}${String(rTP).padEnd(9)}${aTP}`);
  console.log(`${'FN'.padEnd(14)}${String(rFN).padEnd(9)}${aFN}`);
  console.log(`${'FP'.padEnd(14)}${String(rFP).padEnd(9)}${aFP}`);
  console.log(`${'TN'.padEnd(14)}${String(rTN).padEnd(9)}${aTN}`);
  console.log(`${'Detection%'.padEnd(14)}${fmt(rTP,rTP+rFN).padEnd(9)}${fmt(aTP,aTP+aFN)}`);
  console.log(`${'FP rate%'.padEnd(14)}${fmt(rFP,rFP+rTN).padEnd(9)}${fmt(aFP,aFP+aTN)}`);
}
main().catch(console.error);
