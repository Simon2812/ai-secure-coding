/**
 * Re-score the RealVuln cache without re-running inference.
 *
 * The runner drops files whose model call failed, but still counted their
 * labels in the denominator — which understates recall for both columns.
 * This scores both configurations on exactly the files that completed, and
 * removes the excluded files' labels from the denominator too.
 *
 *   node bench/rescoreRealvuln.js
 */

const fs = require("fs");
const path = require("path");

const GT = "C:/temp/realvuln/ground-truth";
const REPOS = "C:/temp/realvuln/repos";
const CACHE = path.join(__dirname, "results-realvuln", "raw.jsonl");

const OURS = new Set([
  "CWE-22", "CWE-78", "CWE-89", "CWE-190", "CWE-259",
  "CWE-321", "CWE-327", "CWE-328", "CWE-416", "CWE-787",
]);
const TOLERANCE = 10;

const normalise = (v) => {
  const m = typeof v === "string" && v.match(/(\d{1,4})/);
  return m ? `CWE-${m[1]}` : null;
};

const acceptSet = (entry) => {
  const s = new Set(entry.acceptable_cwes || []);
  if (entry.primary_cwe) s.add(entry.primary_cwe);
  return s;
};

const inScope = (e) =>
  e.file.endsWith(".py") && [...acceptSet(e)].some((c) => OURS.has(c));

function loadLabels() {
  const byFile = new Map();
  const all = [];
  for (const dir of fs.readdirSync(GT)) {
    if (!dir.startsWith("realvuln-")) continue;
    const gtFile = path.join(GT, dir, "ground-truth.json");
    if (!fs.existsSync(gtFile)) continue;
    if (!fs.existsSync(path.join(REPOS, dir, ".git"))) continue;

    const findings = JSON.parse(fs.readFileSync(gtFile, "utf8")).findings || [];
    for (const entry of findings.filter(inScope)) {
      const key = `${dir}::${entry.file.split("\\").join("/")}`;
      if (!byFile.has(key)) byFile.set(key, []);
      byFile.get(key).push(entry);
      all.push({ key, entry });
    }
  }
  return { byFile, all };
}

const matches = (finding, label) => {
  const cwe = normalise(finding.cwe);
  if (!cwe || !acceptSet(label).has(cwe)) return false;
  const start = (label.location?.start_line ?? 1) - TOLERANCE;
  const end = (label.location?.end_line ?? label.location?.start_line ?? 1) + TOLERANCE;
  return finding.line >= start && finding.line <= end;
};

function main() {
  const { byFile, all } = loadLabels();
  const records = fs.readFileSync(CACHE, "utf8").split("\n")
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const excluded = new Set(
    records.filter((r) => r.error || r.staticError).map((r) => r.key)
  );

  const evaluate = (config) => {
    const hits = new Set();
    const traps = new Set();
    let unlabelled = 0;

    for (const record of records) {
      if (excluded.has(record.key)) continue;
      const findings = config === "static"
        ? record.static || []
        : [...(record.static || []), ...(record.model || [])];
      const labels = byFile.get(record.key) || [];

      for (const finding of findings) {
        const cwe = normalise(finding.cwe);
        if (!cwe || !OURS.has(cwe)) continue;
        const matched = labels.filter((l) => matches(finding, l));
        if (matched.length === 0) { unlabelled++; continue; }
        for (const label of matched) {
          (label.is_vulnerable ? hits : traps).add(`${record.key}#${label.id}`);
        }
      }
    }

    let vulnerable = 0, trapCount = 0;
    for (const { key, entry } of all) {
      if (excluded.has(key)) continue;
      entry.is_vulnerable ? vulnerable++ : trapCount++;
    }

    const tp = hits.size, fp = traps.size;
    const recall = vulnerable ? tp / vulnerable : 0;
    const trapRate = trapCount ? fp / trapCount : 0;
    const precision = tp + fp + unlabelled ? tp / (tp + fp + unlabelled) : 0;
    return {
      vulnerable, trapCount, tp, fn: vulnerable - tp, fp, unlabelled,
      recall, trapRate, precision,
      f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    };
  };

  const pct = (v) => (v * 100).toFixed(1);
  const out = [];
  out.push("\n## RealVuln — real-world Python applications\n");
  out.push(`21 repositories, ${records.length - excluded.size} Python files scored.`);
  out.push(`${excluded.size} files excluded from both columns (model returned malformed JSON); their labels are removed from the denominator so both configurations are scored on an identical file set.`);
  out.push("");
  out.push("| Config | Recall | Trap FP rate | Precision | F1 | TP | FN | Traps tripped | Unlabelled findings |");
  out.push("|---|---|---|---|---|---|---|---|---|");
  for (const name of ["static", "hybrid"]) {
    const m = evaluate(name);
    out.push(
      `| ${name === "static" ? "Static" : "Hybrid"} | ${pct(m.recall)}% | ${pct(m.trapRate)}% | ` +
      `${pct(m.precision)}% | ${pct(m.f1)}% | ${m.tp} | ${m.fn} | ${m.fp}/${m.trapCount} | ${m.unlabelled} |`
    );
  }
  const text = out.join("\n");
  fs.writeFileSync(path.join(__dirname, "results-realvuln", "results.md"), text, "utf8");
  console.log(text);
}

main();
