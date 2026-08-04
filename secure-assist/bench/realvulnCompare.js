/**
 * Like-for-like comparison against the scanners RealVuln published.
 *
 * RealVuln's own leaderboard scores every tool across all 796 labelled
 * findings. SecureAssist only claims ten CWEs, so that comparison would be
 * meaningless. This scores every scanner's raw output against the identical
 * subset — the same labels, the same repositories, the same matcher, the
 * same excluded files — so the numbers are directly comparable.
 *
 *   node bench/realvulnCompare.js
 */

const fs = require("fs");
const path = require("path");

const ROOT = "C:/temp/realvuln";
const GT = path.join(ROOT, "ground-truth");
const REPOS = path.join(ROOT, "repos");
const SCANS = path.join(ROOT, "scan-results");
const CACHE = path.join(__dirname, "results-realvuln", "raw.jsonl");

const OURS = new Set([
  "CWE-22", "CWE-78", "CWE-89", "CWE-190", "CWE-259",
  "CWE-321", "CWE-327", "CWE-328", "CWE-416", "CWE-787",
]);
const TOLERANCE = 10;

/** Scanners to report. Everything in scan-results/ is available. */
const SCANNERS = [
  "semgrep",
  "snyk",
  "sonarqube",
  "claude-opus-5-cc-agentic-v1",
  "claude-sonnet-4-6-agentic-v1",
  "gpt-5.5-agentic-v1",
  "gemini-3.1-pro-agentic-v1",
  "deepseek-v4-pro-agentic-v1",
  "qwen-3.5-397b-agentic-v1",
  "kolega-devsec-max-v0.0.1",
];

const normalise = (v) => {
  const m = typeof v === "string" && v.match(/CWE[-_ ]?(\d{1,4})/i);
  return m ? `CWE-${m[1]}` : null;
};

const acceptSet = (entry) => {
  const s = new Set(entry.acceptable_cwes || []);
  if (entry.primary_cwe) s.add(entry.primary_cwe);
  return s;
};

const inScope = (e) =>
  e.file.endsWith(".py") && [...acceptSet(e)].some((c) => OURS.has(c));

/* ------------------------------------------------------------------ */

function loadLabels(repoIds) {
  const byFile = new Map();
  const all = [];
  for (const dir of repoIds) {
    const gtFile = path.join(GT, dir, "ground-truth.json");
    if (!fs.existsSync(gtFile)) continue;
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
  if (!finding.cwes.some((c) => acceptSet(label).has(c))) return false;
  const start = (label.location?.start_line ?? 1) - TOLERANCE;
  const end = (label.location?.end_line ?? label.location?.start_line ?? 1) + TOLERANCE;
  return finding.line >= start && finding.line <= end;
};

/** Read one scanner's findings for one repo, normalised to {key,line,cwes}. */
function readScanner(repoId, scanner) {
  const dir = path.join(SCANS, repoId, scanner);
  if (!fs.existsSync(dir)) return [];

  const files = fs.readdirSync(dir)
    .filter((f) => f.endsWith(".json") && !f.endsWith(".metrics.json"));
  if (files.length === 0) return [];

  // Multiple runs exist for some scanners; take the first deterministically.
  const payloadPath = path.join(dir, files.sort()[0]);
  let payload;
  try { payload = JSON.parse(fs.readFileSync(payloadPath, "utf8")); }
  catch { return []; }

  const out = [];
  for (const r of payload.results ?? []) {
    const rel = String(r.path ?? "").split("\\").join("/").replace(/^\.\//, "");
    // Scanners disagree on shape: some emit an array of CWE strings, some a
    // single string, some nest it under a different key.
    const raw = r.extra?.metadata?.cwe ?? r.extra?.metadata?.cwe_id ?? [];
    const cwes = [...new Set(
      (Array.isArray(raw) ? raw : [raw])
        .map(normalise)
        .filter((c) => c && OURS.has(c))
    )];
    if (cwes.length === 0) continue;          // out of our scope
    out.push({ key: `${repoId}::${rel}`, line: r.start?.line ?? 0, cwes });
  }
  return out;
}

/** Score a flat list of findings against the labels. */
function evaluate(findings, byFile, all, excluded) {
  const hits = new Set();
  const traps = new Set();
  let unlabelled = 0;

  for (const finding of findings) {
    if (excluded.has(finding.key)) continue;
    const labels = byFile.get(finding.key) || [];
    const matched = labels.filter((l) => matches(finding, l));
    if (matched.length === 0) { unlabelled++; continue; }
    for (const label of matched) {
      (label.is_vulnerable ? hits : traps).add(`${finding.key}#${label.id}`);
    }
  }

  let vulnerable = 0, trapCount = 0;
  for (const { key, entry } of all) {
    if (excluded.has(key)) continue;
    entry.is_vulnerable ? vulnerable++ : trapCount++;
  }

  const tp = hits.size, fp = traps.size;
  const recall = vulnerable ? tp / vulnerable : 0;
  const precision = tp + fp + unlabelled ? tp / (tp + fp + unlabelled) : 0;
  const fBeta = (b) => {
    const b2 = b * b;
    return b2 * precision + recall ? ((1 + b2) * precision * recall) / (b2 * precision + recall) : 0;
  };
  return {
    tp, fn: vulnerable - tp, fp, trapCount, unlabelled,
    recall, precision, trapRate: trapCount ? fp / trapCount : 0,
    f1: fBeta(1), f3: fBeta(3),
  };
}

/* ------------------------------------------------------------------ */

function main() {
  const repoIds = fs.readdirSync(REPOS)
    .filter((d) => fs.existsSync(path.join(REPOS, d, ".git")));

  const { byFile, all } = loadLabels(repoIds);

  const records = fs.readFileSync(CACHE, "utf8").split("\n")
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  // The same files are excluded for every tool, so the denominator matches.
  const excluded = new Set(
    records.filter((r) => r.error || r.staticError).map((r) => r.key)
  );

  const rows = [];

  for (const config of ["static", "hybrid"]) {
    const findings = [];
    for (const record of records) {
      const list = config === "static"
        ? record.static || []
        : [...(record.static || []), ...(record.model || [])];
      for (const f of list) {
        const cwe = normalise(f.cwe);
        if (cwe && OURS.has(cwe)) findings.push({ key: record.key, line: f.line ?? 0, cwes: [cwe] });
      }
    }
    rows.push([`SecureAssist (${config})`, evaluate(findings, byFile, all, excluded)]);
  }

  for (const scanner of SCANNERS) {
    const findings = [];
    for (const repoId of repoIds) findings.push(...readScanner(repoId, scanner));
    if (findings.length === 0 && !fs.existsSync(path.join(SCANS, repoIds[0], scanner))) continue;
    rows.push([scanner, evaluate(findings, byFile, all, excluded)]);
  }

  rows.sort((a, b) => b[1].f3 - a[1].f3);

  const pct = (v) => (v * 100).toFixed(1);
  const out = [];
  out.push("\n## RealVuln — like-for-like comparison\n");
  out.push(`All tools scored on the identical subset: ${repoIds.length} repositories, only the ten CWEs SecureAssist covers, only .py files, same ±${TOLERANCE}-line matcher, same ${excluded.size} excluded files.`);
  out.push("");
  out.push("| Tool | Recall | Precision | F1 | F3 | TP | FN | Traps tripped | Unlabelled |");
  out.push("|---|---|---|---|---|---|---|---|---|");
  for (const [name, m] of rows) {
    const bold = name.startsWith("SecureAssist") ? "**" : "";
    out.push(
      `| ${bold}${name}${bold} | ${pct(m.recall)}% | ${pct(m.precision)}% | ${pct(m.f1)} | ` +
      `${pct(m.f3)} | ${m.tp} | ${m.fn} | ${m.fp}/${m.trapCount} | ${m.unlabelled} |`
    );
  }
  out.push("");
  out.push("F3 weights recall nine times precision, matching RealVuln's headline metric. Note these figures are NOT comparable to RealVuln's published leaderboard, which scores all 796 findings across every CWE; this table is restricted to the ten CWEs SecureAssist implements.");

  const text = out.join("\n");
  fs.writeFileSync(path.join(__dirname, "results-realvuln", "comparison.md"), text, "utf8");
  console.log(text);
}

main();
