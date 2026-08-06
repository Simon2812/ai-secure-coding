import * as fs from "fs";
import * as path from "path";
import { analyzeCode } from "../analyzer/analyze";
import { initAstAnalyzer, astAnalyzeCode } from "../analyzer/ast/astAnalyzer";

const REPO_ROOT = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(__dirname, "..", "..", "..");
const METADATA_DIR = path.join(REPO_ROOT, "dataset", "metadata");

interface Stats { tp: number; fn: number; fp: number; tn: number }

function walkJson(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) results.push(...walkJson(fullPath));
    else if (entry.name.endsWith(".json")) results.push(fullPath);
  }
  return results;
}

function bucket(stats: Record<string, Stats>, cwe: string, isVuln: boolean, hasFindings: boolean) {
  if (!stats[cwe]) stats[cwe] = { tp: 0, fn: 0, fp: 0, tn: 0 };
  if (isVuln && hasFindings)          stats[cwe].tp++;
  else if (isVuln && !hasFindings)    stats[cwe].fn++;
  else if (!isVuln && hasFindings)    stats[cwe].fp++;
  else                                stats[cwe].tn++;
}

function totals(stats: Record<string, Stats>) {
  let tp = 0, fn = 0, fp = 0, tn = 0;
  for (const s of Object.values(stats)) { tp += s.tp; fn += s.fn; fp += s.fp; tn += s.tn; }
  return { tp, fn, fp, tn };
}

function pct(a: number, b: number) { return b > 0 ? (a / b * 100).toFixed(1) + "%" : "N/A"; }

async function main() {
  await initAstAnalyzer();
  const files = walkJson(METADATA_DIR);

  const regexStats: Record<string, Stats> = {};
  const astStats: Record<string, Stats> = {};

  for (const metaPath of files) {
    const meta = JSON.parse(fs.readFileSync(metaPath, "utf-8"));
    const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ""));
    if (!fs.existsSync(codePath)) continue;

    const code = fs.readFileSync(codePath, "utf-8");
    const isVuln = meta.vulnerabilities.length > 0;
    const rel = path.relative(METADATA_DIR, metaPath);
    const cwe = rel.split(path.sep)[0];

    const regexFindings = analyzeCode(code, codePath);
    const astFindings = astAnalyzeCode(code, codePath);

    bucket(regexStats, cwe, isVuln, regexFindings.length > 0);
    bucket(astStats, cwe, isVuln, astFindings.length > 0);
  }

  const pad = (s: string | number, n: number) => String(s).padStart(n);
  const lpad = (s: string, n: number) => s.padEnd(n);

  console.log("\n" + lpad("CWE", 15) +
    pad("AST TP", 8) + pad("FN", 5) + pad("FP", 5) + pad("TN", 5) +
    pad("Det%", 7) + pad("FP%", 7));
  console.log("-".repeat(57));

  const allCwes = new Set([...Object.keys(regexStats), ...Object.keys(astStats)]);
  for (const cwe of [...allCwes].sort()) {
    const a = astStats[cwe] ?? { tp: 0, fn: 0, fp: 0, tn: 0 };
    const av = a.tp + a.fn;
    const as_ = a.fp + a.tn;
    console.log(
      lpad(cwe, 15) +
      pad(a.tp, 8) + pad(a.fn, 5) + pad(a.fp, 5) + pad(a.tn, 5) +
      pad(pct(a.tp, av), 7) + pad(pct(a.fp, as_), 7)
    );
  }

  const r = totals(regexStats), a = totals(astStats);
  const rv = r.tp + r.fn, av = a.tp + a.fn;
  const rs = r.fp + r.tn, as_ = a.fp + a.tn;
  console.log("-".repeat(57));
  console.log(
    lpad("TOTAL", 15) +
    pad(a.tp, 8) + pad(a.fn, 5) + pad(a.fp, 5) + pad(a.tn, 5) +
    pad(pct(a.tp, av), 7) + pad(pct(a.fp, as_), 7)
  );
  console.log(`\nRegex → Detection: ${pct(r.tp, rv)}  FP rate: ${pct(r.fp, rs)}`);
  console.log(`AST   → Detection: ${pct(a.tp, av)}  FP rate: ${pct(a.fp, as_)}`);
}

main().catch(e => { console.error(e); process.exit(1); });
