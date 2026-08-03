import { initAstAnalyzer, astAnalyzeCode } from '../../analyzer/ast/astAnalyzer';
import * as fs from 'fs';

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

async function main() {
  await initAstAnalyzer();
  const f = 'C:/temp/juliet_sample.c';
  const code = fs.readFileSync(f, 'utf-8');
  const bad  = stripBlock(code, 'OMITGOOD');
  const good = stripBlock(code, 'OMITBAD');

  console.log(`orig lines=${code.split('\n').length}  bad lines=${bad.split('\n').length}  good lines=${good.split('\n').length}`);
  console.log(`bad === good ? ${bad === good}`);
  console.log(`bad contains '_bad(' ? ${bad.includes('_bad(')}   contains 'goodG2B' ? ${bad.includes('goodG2B')}`);
  console.log(`good contains '_bad(' ? ${good.includes('_bad(')}  contains 'goodG2B' ? ${good.includes('goodG2B')}`);
  console.log(`\nbad  findings CWE-190: ${astAnalyzeCode(bad,  f).filter(x=>x.cweId==='CWE-190').map(x=>'L'+x.line).join(',') || 'none'}`);
  console.log(`good findings CWE-190: ${astAnalyzeCode(good, f).filter(x=>x.cweId==='CWE-190').map(x=>'L'+x.line).join(',') || 'none'}`);
}
main().catch(console.error);
