import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import { findCommandInjection } from '../../analyzer/rules/commandInjection';
import { detectLanguage } from '../../analyzer/utils';
import * as fs from 'fs';

function regexCwe78(code: string, filePath: string) {
  return findCommandInjection({ code, filePath, language: detectLanguage(filePath) });
}

const FILES: { path: string; expect: 'VULN' | 'SAFE' }[] = [
  // Python
  { path: 'C:/temp/cwe78-fresh/python/vuln_os_system.py',       expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_subprocess_shell.py', expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_popen_concat.py',     expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_subprocess_env.py',   expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_check_output.py',     expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_input_kwarg.py',      expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/vuln_asyncio_shell.py',    expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/python/safe_subprocess_list.py',  expect: 'SAFE' },
  { path: 'C:/temp/cwe78-fresh/python/safe_allowlist.py',        expect: 'SAFE' },
  { path: 'C:/temp/cwe78-fresh/python/safe_no_shell.py',         expect: 'SAFE' },
  // Java
  { path: 'C:/temp/cwe78-fresh/java/VulnRuntimeExec.java',       expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/java/VulnProcessBuilder.java',    expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/java/VulnRuntimeExecArray.java',  expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/java/VulnMultiStepCmd.java',      expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/java/SafeProcessBuilderList.java',expect: 'SAFE' },
  { path: 'C:/temp/cwe78-fresh/java/SafeFixedCommand.java',      expect: 'SAFE' },
  { path: 'C:/temp/cwe78-fresh/java/SafeAllowlistCmd.java',      expect: 'SAFE' },
  // C
  { path: 'C:/temp/cwe78-fresh/c/vuln_system_argv.c',            expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/c/vuln_popen.c',                  expect: 'VULN' },
  { path: 'C:/temp/cwe78-fresh/c/safe_execv.c',                  expect: 'SAFE' },
];

function verdict(hit: boolean, expect: 'VULN' | 'SAFE') {
  if (expect === 'VULN') return hit ? '✓ TP' : '✗ FN';
  return hit ? '✗ FP' : '✓ TN';
}

async function main() {
  await initAstAnalyzer();

  let rTP=0,rFN=0,rFP=0,rTN=0;
  let aTP=0,aFN=0,aFP=0,aTN=0;

  console.log(`\n${'File'.padEnd(38)} Expect  Regex    AST`);
  console.log('─'.repeat(68));

  for (const { path: fp, expect } of FILES) {
    const code = fs.readFileSync(fp, 'utf-8');
    const label = fp.split('/').slice(-2).join('/');

    const rHit = regexCwe78(code, fp).length > 0;
    const aHit = astAnalyzeCode(code, fp).some(f => f.cweId === 'CWE-78');

    const rv = verdict(rHit, expect);
    const av = verdict(aHit, expect);

    if (expect === 'VULN') { rHit ? rTP++ : rFN++; aHit ? aTP++ : aFN++; }
    else                   { rHit ? rFP++ : rTN++; aHit ? aFP++ : aTN++; }

    const flag = rv !== av ? ' ◄' : '';
    console.log(`${label.padEnd(38)} ${expect.padEnd(7)} ${rv.padEnd(8)} ${av}${flag}`);
  }

  const fmt = (a:number,b:number) => b > 0 ? (a/b*100).toFixed(0)+'%' : 'N/A';
  console.log('\n' + '─'.repeat(68));
  console.log(`${''.padEnd(45)}Regex    AST`);
  console.log(`${'TP'.padEnd(45)}${String(rTP).padEnd(9)}${aTP}`);
  console.log(`${'FN'.padEnd(45)}${String(rFN).padEnd(9)}${aFN}`);
  console.log(`${'FP'.padEnd(45)}${String(rFP).padEnd(9)}${aFP}`);
  console.log(`${'TN'.padEnd(45)}${String(rTN).padEnd(9)}${aTN}`);
  console.log(`${'Detection%'.padEnd(45)}${fmt(rTP,rTP+rFN).padEnd(9)}${fmt(aTP,aTP+aFN)}`);
  console.log(`${'FP rate%'.padEnd(45)}${fmt(rFP,rFP+rTN).padEnd(9)}${fmt(aFP,aFP+aTN)}`);
}
main().catch(console.error);
