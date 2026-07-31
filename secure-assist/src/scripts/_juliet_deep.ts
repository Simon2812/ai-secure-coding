import { initAstAnalyzer, astAnalyzeCode } from './ast/astAnalyzer';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = 'C:/temp/juliet/testcases';

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

// Remove a C function by name via brace matching: `... name( ... ) { ... }`
function removeFunction(code: string, nameRe: RegExp): string {
  const idx = code.search(nameRe);
  if (idx < 0) return code;
  const braceStart = code.indexOf('{', idx);
  if (braceStart < 0) return code;
  let depth = 0, i = braceStart;
  for (; i < code.length; i++) {
    if (code[i] === '{') depth++;
    else if (code[i] === '}') { depth--; if (depth === 0) { i++; break; } }
  }
  // back up to start of the line the signature is on
  let sigStart = code.lastIndexOf('\n', idx) + 1;
  return code.slice(0, sigStart) + code.slice(i);
}

function walkC(dir: string): string[] {
  const r: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) r.push(...walkC(full));
    else if (e.name.endsWith('.c')) r.push(full);
  }
  return r;
}

async function main() {
  await initAstAnalyzer();
  const cwe = 'CWE-190';
  const files = walkC(path.join(ROOT, 'CWE190_Integer_Overflow'));

  let bothFire=0, neither=0, discriminated=0, weird=0;
  // guarded-good test: how often we fire on goodB2G ALONE (goodG2B removed)
  let g2gTested=0, firedOnGuardedGood=0;

  for (const f of files) {
    const code = fs.readFileSync(f, 'utf-8');
    const bad  = stripBlock(code, 'OMITGOOD');
    const good = stripBlock(code, 'OMITBAD');
    const badHit  = astAnalyzeCode(bad,  f).some(x => x.cweId === cwe);
    const goodHit = astAnalyzeCode(good, f).some(x => x.cweId === cwe);

    if (badHit && goodHit) bothFire++;
    else if (!badHit && !goodHit) neither++;
    else if (badHit && !goodHit) discriminated++;
    else weird++;

    // Isolate the guarded good path: take good variant, remove goodG2B (which keeps the bad sink)
    if (good.includes('goodB2G') && good.includes('goodG2B')) {
      const guardedOnly = removeFunction(good, /static\s+void\s+goodG2B/);
      if (guardedOnly.includes('goodB2G') && !guardedOnly.includes('goodG2B')) {
        g2gTested++;
        if (astAnalyzeCode(guardedOnly, f).some(x => x.cweId === cwe)) firedOnGuardedGood++;
      }
    }
  }

  console.log(`\nCWE-190 per-file 2x2 (${files.length} files):`);
  console.log(`  both fire (bad+good):      ${bothFire}`);
  console.log(`  neither fires:             ${neither}`);
  console.log(`  DISCRIMINATED (bad only):  ${discriminated}`);
  console.log(`  weird (good only):         ${weird}`);
  console.log(`\nGuarded-good test (goodB2G alone, goodG2B removed):`);
  console.log(`  files tested:              ${g2gTested}`);
  console.log(`  fired on GUARDED good:     ${firedOnGuardedGood}  (${(firedOnGuardedGood/g2gTested*100).toFixed(0)}%)`);
  console.log(`  => ${g2gTested - firedOnGuardedGood} guarded-good cases correctly NOT flagged`);
}
main().catch(console.error);
