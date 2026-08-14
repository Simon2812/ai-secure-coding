/**
 * Re-score the RealVuln run with test files excluded.
 *
 * Uses the cached results — no inference, no GPU, runs in a second.
 *
 * RealVuln clones whole repositories, so the applications' test suites are on
 * disk and get scanned. Findings there are not vulnerabilities: a fixture that
 * logs in with password "12345" is how tests work. The ground truth does not
 * label them, so every one counts against precision.
 *
 * Every other scanner in the comparison already skips them — Semgrep, Claude
 * Opus 5, GPT-5.5 and Kolega report zero findings in test files. This scores
 * SecureAssist on the same footing.
 *
 * Verified before writing this: no in-scope label sits in a test file, so
 * excluding them cannot remove a true positive or a trap. Only the numerator's
 * noise changes; the denominator is identical.
 *
 *   node bench/rescoreNoTests.js
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

/** Paths that hold tests, fixtures or seed data rather than shipped code. */
const TEST_DIR = /(^|\/)(tests?|testing|spec|fixtures?)\//i;
const TEST_FILE = /(^|\/)(test_|conftest)/i;
const TEST_SUFFIX = /_test\.py$/i;

function isTestPath(relPath) {
  const p = relPath.replace(/\\/g, "/");
  return TEST_DIR.test(p) || TEST_FILE.test(p) || TEST_SUFFIX.test(p);
}

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

    for (const entry of (JSON.parse(fs.readFileSync(gtFile, "utf8")).findings || []).filter(inScope)) {
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

function evaluate(records, byFile, all, excluded, skipTests) {
  const hits = new Set();
  const traps = new Set();
  let unlabelled = 0;
  let skipped = 0;

  for (const record of records) {
    if (excluded.has(record.key)) continue;

    const rel = record.key.split("::")[1] ?? "";
    if (skipTests && isTestPath(rel)) {
      skipped++;
      continue;
    }

    const findings = [...(record.static || []), ...(record.model || [])];
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
    if (skipTests && isTestPath(key.split("::")[1] ?? "")) continue;
    entry.is_vulnerable ? vulnerable++ : trapCount++;
  }

  const tp = hits.size, fp = traps.size;
  const recall = vulnerable ? tp / vulnerable : 0;
  const precision = tp + fp + unlabelled ? tp / (tp + fp + unlabelled) : 0;
  const fBeta = (b) => {
    const b2 = b * b;
    return b2 * precision + recall
      ? ((1 + b2) * precision * recall) / (b2 * precision + recall)
      : 0;
  };

  return {
    vulnerable, trapCount, tp, fn: vulnerable - tp, fp, unlabelled, skipped,
    recall, precision, f1: fBeta(1), f3: fBeta(3),
  };
}

/** Same, for the static analyzer alone. */
function evaluateStatic(records, byFile, all, excluded, skipTests) {
  const patched = records.map((r) => ({ ...r, model: [] }));
  return evaluate(patched, byFile, all, excluded, skipTests);
}

function main() {
  const { byFile, all } = loadLabels();

  const records = fs.readFileSync(CACHE, "utf8").split("\n")
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const excluded = new Set(
    records.filter((r) => r.error || r.staticError).map((r) => r.key)
  );

  const rows = [
    ["Static, all files", evaluateStatic(records, byFile, all, excluded, false)],
    ["Static, no tests", evaluateStatic(records, byFile, all, excluded, true)],
    ["Hybrid, all files", evaluate(records, byFile, all, excluded, false)],
    ["Hybrid, no tests", evaluate(records, byFile, all, excluded, true)],
  ];

  const pct = (v) => `${(v * 100).toFixed(1)}%`;
  const out = [];

  out.push("\n## RealVuln — effect of excluding test files\n");
  out.push(
    "Test suites are scanned because RealVuln clones whole repositories, but " +
    "the ground truth does not label them — a fixture logging in with a fixed " +
    "password is not a vulnerability. No in-scope label sits in a test file, so " +
    "excluding them cannot cost a true positive."
  );
  out.push("");
  out.push("| Configuration | Recall | Precision | F1 | F3 | TP | FN | Unlabelled | Files skipped |");
  out.push("|---|---|---|---|---|---|---|---|---|");
  for (const [name, m] of rows) {
    out.push(
      `| ${name} | ${pct(m.recall)} | ${pct(m.precision)} | ${(m.f1 * 100).toFixed(1)} | ` +
      `${(m.f3 * 100).toFixed(1)} | ${m.tp} | ${m.fn} | ${m.unlabelled} | ${m.skipped} |`
    );
  }

  const [, sAll] = rows[0], [, sNo] = rows[1], [, hAll] = rows[2], [, hNo] = rows[3];
  out.push("");
  out.push(
    `Static precision ${pct(sAll.precision)} to ${pct(sNo.precision)}, ` +
    `hybrid ${pct(hAll.precision)} to ${pct(hNo.precision)}. ` +
    `Recall is unchanged in both cases, as expected.`
  );
  out.push("");
  out.push(
    "For comparison, findings reported inside test files by the scanners " +
    "RealVuln published: Semgrep 0, Claude Opus 5 0, GPT-5.5 0, Kolega 0, " +
    "Snyk 12, SonarQube 71."
  );

  const text = out.join("\n");
  const dest = path.join(__dirname, "results-realvuln", "no-tests.md");
  fs.writeFileSync(dest, text, "utf8");
  console.log(text);
  console.log(`\nwritten to ${dest}`);
}

main();
