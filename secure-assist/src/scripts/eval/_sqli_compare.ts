import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import { findSqlInjection } from '../analyzer/rules/sqlInjection';
import { detectLanguage } from '../analyzer/utils';
import * as fs from 'fs';

async function main() {
  await initAstAnalyzer();
  const filePath = 'C:/temp/sqli_test.py';
  const code = fs.readFileSync(filePath, 'utf-8');
  const lines = code.split('\n');
  const ctx = { code, filePath, language: detectLanguage(filePath) };

  const rLines = new Set(findSqlInjection(ctx).map(f => f.line));
  const aLines = new Set(astAnalyzeCode(code, filePath).filter(f => f.cweId === 'CWE-89').map(f => f.line));

  // Functions and their expected verdicts
  const FUNCTIONS: { name: string; line: number; expect: 'VULN' | 'SAFE' }[] = [
    { name: 'safe_parameterized_sqlite',         line: 38,  expect: 'SAFE' },
    { name: 'safe_parameterized_id',             line: 46,  expect: 'SAFE' },
    { name: 'safe_named_parameters',             line: 53,  expect: 'SAFE' },
    { name: 'safe_constant_query',               line: 61,  expect: 'SAFE' },
    { name: 'safe_query_variable_constant',      line: 66,  expect: 'SAFE' },
    { name: 'safe_parameterized_query_variable', line: 72,  expect: 'SAFE' },
    { name: 'vuln_inline_fstring',               line: 77,  expect: 'VULN' },
    { name: 'vuln_inline_concat',                line: 82,  expect: 'VULN' },
    { name: 'vuln_inline_percent_formatting',    line: 87,  expect: 'VULN' },
    { name: 'vuln_query_variable_fstring',       line: 92,  expect: 'VULN' },
    { name: 'vuln_query_variable_concat',        line: 98,  expect: 'VULN' },
    { name: 'vuln_query_variable_percent_fmt',   line: 104, expect: 'VULN' },
    { name: 'vuln_multiple_inputs',              line: 110, expect: 'VULN' },
    { name: 'vuln_like_clause_concat',           line: 116, expect: 'VULN' },
    { name: 'edge_dynamic_table_name',           line: 122, expect: 'SAFE' },
    { name: 'edge_wrapper_function',             line: 127, expect: 'VULN' },
    { name: 'edge_sanitized_input',              line: 134, expect: 'VULN' },
  ];

  // Find which line number within each function's range fired
  function hitInRange(set: Set<number>, start: number, nextStart: number): boolean {
    for (const ln of set) {
      if (ln >= start && ln < nextStart) return true;
    }
    return false;
  }

  console.log('\nFunction'.padEnd(36) + 'Expect  Regex   AST');
  console.log('─'.repeat(65));

  for (let i = 0; i < FUNCTIONS.length; i++) {
    const fn = FUNCTIONS[i];
    const nextLine = FUNCTIONS[i + 1]?.line ?? 999;
    const rHit = hitInRange(rLines, fn.line, nextLine);
    const aHit = hitInRange(aLines, fn.line, nextLine);

    const rVerdict = fn.expect === 'VULN'
      ? (rHit ? '✓ TP' : '✗ FN')
      : (rHit ? '✗ FP' : '✓ TN');
    const aVerdict = fn.expect === 'VULN'
      ? (aHit ? '✓ TP' : '✗ FN')
      : (aHit ? '✗ FP' : '✓ TN');

    console.log(`${fn.name.padEnd(36)}${fn.expect.padEnd(8)}${rVerdict.padEnd(8)}${aVerdict}`);
  }

  // Tally
  let rTP=0,rFN=0,rFP=0,rTN=0,aTP=0,aFN=0,aFP=0,aTN=0;
  for (let i = 0; i < FUNCTIONS.length; i++) {
    const fn = FUNCTIONS[i];
    const nextLine = FUNCTIONS[i + 1]?.line ?? 999;
    const rHit = hitInRange(rLines, fn.line, nextLine);
    const aHit = hitInRange(aLines, fn.line, nextLine);
    if (fn.expect === 'VULN') { rHit ? rTP++ : rFN++; aHit ? aTP++ : aFN++; }
    else                      { rHit ? rFP++ : rTN++; aHit ? aFP++ : aTN++; }
  }

  const fmt = (a:number,b:number) => b>0 ? (a/b*100).toFixed(0)+'%' : 'N/A';
  console.log('\n' + '─'.repeat(65));
  console.log(`${''.padEnd(36)}${''.padEnd(8)}Regex   AST`);
  console.log(`${'TP'.padEnd(36)}${''.padEnd(8)}${String(rTP).padEnd(8)}${aTP}`);
  console.log(`${'FN'.padEnd(36)}${''.padEnd(8)}${String(rFN).padEnd(8)}${aFN}`);
  console.log(`${'FP'.padEnd(36)}${''.padEnd(8)}${String(rFP).padEnd(8)}${aFP}`);
  console.log(`${'TN'.padEnd(36)}${''.padEnd(8)}${String(rTN).padEnd(8)}${aTN}`);
  console.log(`${'Detection%'.padEnd(36)}${''.padEnd(8)}${fmt(rTP,rTP+rFN).padEnd(8)}${fmt(aTP,aTP+aFN)}`);
  console.log(`${'FP rate%'.padEnd(36)}${''.padEnd(8)}${fmt(rFP,rFP+rTN).padEnd(8)}${fmt(aFP,aFP+aTN)}`);
}
main().catch(console.error);
