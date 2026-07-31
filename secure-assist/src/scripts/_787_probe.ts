import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';

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

async function main() {
  await initAstAnalyzer();
  const files = [
    'CWE121_Stack_Based_Buffer_Overflow/s02/CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_01.c',
    'CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c',
  ];
  for (const rel of files) {
    const f = 'C:/temp/juliet/testcases/' + rel;
    const code = fs.readFileSync(f, 'utf-8');
    const bad = stripBlock(code, 'OMITGOOD');
    const all = astAnalyzeCode(bad, f);
    console.log(`\n${rel.split('/').pop()}`);
    console.log(`  ALL findings on BAD variant (${all.length}):`);
    all.forEach(x => console.log(`     ${x.cweId}  L${x.line}  ${x.message}`));
    if (all.length === 0) console.log('     (analyzer detects NOTHING)');
  }
}
main().catch(console.error);
