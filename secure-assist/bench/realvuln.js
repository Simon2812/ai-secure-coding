/**
 * RealVuln benchmark runner.
 *
 * Scores the static analyzer and the hybrid configuration against RealVuln —
 * 26 intentionally-vulnerable real-world Python applications with third-party
 * hand-labelled ground truth, including deliberate false-positive traps.
 *
 * This differs from the OWASP/Juliet harness in an important way. There, each
 * test case is a self-contained file with one verdict. Here we scan whole
 * repositories and match each finding to a labelled entry by file, CWE and
 * line proximity — the same matching RealVuln's own scorer uses.
 *
 * Scope is restricted to the ten CWEs the analyzer claims to cover; RealVuln
 * labels many others (XSS, CSRF, SSRF, access control) which are not scored.
 *
 *   node bench/realvuln.js [--static-only] [--dry-run] [--fresh]
 */

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const ROOT = "C:/temp/realvuln";
const REPOS = path.join(ROOT, "repos");
const GROUND_TRUTH = path.join(ROOT, "ground-truth");
const OUT = path.join(__dirname, "results-realvuln");
const ENDPOINT = "http://localhost:8000";

/** The CWEs the analyzer covers. Everything else in the corpus is out of scope. */
const OURS = new Set([
  "CWE-22", "CWE-78", "CWE-89", "CWE-190", "CWE-259",
  "CWE-321", "CWE-327", "CWE-328", "CWE-416", "CWE-787",
]);

/** RealVuln matches a finding to a label within this many lines. */
const LINE_TOLERANCE = 10;

const SKIP_DIRS = /[\\/](\.git|venv|\.venv|node_modules|migrations|__pycache__|site-packages)[\\/]/;

/* ------------------------------------------------------------------ */

function normaliseCwe(value) {
  if (typeof value !== "string") return undefined;
  const m = value.match(/(\d{1,4})/);
  return m ? `CWE-${m[1]}` : undefined;
}

/** Accept set for a label: its primary CWE plus any the benchmark allows. */
function acceptSet(entry) {
  const set = new Set(entry.acceptable_cwes ?? []);
  if (entry.primary_cwe) set.add(entry.primary_cwe);
  return set;
}

/**
 * A label is in scope when it names a CWE we cover *and* sits in a Python
 * source file. RealVuln also labels findings in templates and config
 * (.html, .xml, .yml); those are unreachable for a Python source analyzer,
 * so counting them would measure file-type coverage rather than detection.
 * Three such labels are excluded on the available repositories.
 */
const inScope = (entry) =>
  entry.file.endsWith(".py") && [...acceptSet(entry)].some((c) => OURS.has(c));

/**
 * Load labels for every repository that was successfully cloned, keyed by
 * "<repoId>::<relative path>" so lookups during scanning are direct.
 */
function loadGroundTruth() {
  const byFile = new Map();
  const repos = [];

  for (const dir of fs.readdirSync(GROUND_TRUTH)) {
    if (!dir.startsWith("realvuln-")) continue;
    const gtPath = path.join(GROUND_TRUTH, dir, "ground-truth.json");
    const repoPath = path.join(REPOS, dir);
    if (!fs.existsSync(gtPath)) continue;
    if (!fs.existsSync(path.join(repoPath, ".git"))) continue; // clone unavailable

    const gt = JSON.parse(fs.readFileSync(gtPath, "utf8"));
    const labels = (gt.findings ?? []).filter(inScope);
    if (labels.length === 0) continue;

    repos.push({ id: dir, root: repoPath, labels });

    for (const label of labels) {
      const key = `${dir}::${label.file.replace(/\\/g, "/")}`;
      if (!byFile.has(key)) byFile.set(key, []);
      byFile.get(key).push(label);
    }
  }

  return { repos, byFile };
}

function pythonFiles(root) {
  const out = [];
  const walk = (dir) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (SKIP_DIRS.test(full + path.sep)) continue;
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith(".py")) out.push(full);
    }
  };
  walk(root);
  return out;
}

/* ------------------------------------------------------------------ */

function analyzeWithModel(code, staticFindings) {
  const url = new URL(`${ENDPOINT}/analyze`);
  const body = JSON.stringify({ code, analysis: staticFindings });
  const lib = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname: url.hostname, port: url.port, path: url.pathname, method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            try { resolve(JSON.parse(data)); }
            catch { reject(new Error(`invalid JSON: ${data.slice(0, 160)}`)); }
          } else reject(new Error(`HTTP ${status}: ${data.slice(0, 160)}`));
        });
      }
    );
    req.setTimeout(300_000, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function analyzeWithRetry(code, findings, attempts = 3) {
  let last;
  for (let i = 1; i <= attempts; i++) {
    try { return await analyzeWithModel(code, findings); }
    catch (err) {
      last = err;
      if (/^HTTP [45]\d\d/.test(String(err.message))) throw err;
      if (i < attempts) await sleep(2000 * i);
    }
  }
  throw last;
}

/* ------------------------------------------------------------------ *
 * Matching and scoring
 * ------------------------------------------------------------------ */

/** A finding matches a label when the CWE is acceptable and the line is close. */
function matches(finding, label) {
  const cwe = normaliseCwe(finding.cwe);
  if (!cwe || !acceptSet(label).has(cwe)) return false;
  const start = (label.location?.start_line ?? 1) - LINE_TOLERANCE;
  const end = (label.location?.end_line ?? label.location?.start_line ?? 1) + LINE_TOLERANCE;
  return finding.line >= start && finding.line <= end;
}

function score(records, byFile, repos) {
  const config = { static: {}, hybrid: {} };

  for (const name of ["static", "hybrid"]) {
    const matched = new Set();       // label ids hit by a real detection
    const trapsTripped = new Set();  // false-positive traps hit
    let unlabelled = 0;              // findings matching nothing at all

    for (const record of records) {
      if (record.error) continue;
      const findings = name === "static"
        ? record.static ?? []
        : [...(record.static ?? []), ...(record.model ?? [])];

      const labels = byFile.get(record.key) ?? [];

      for (const finding of findings) {
        const cwe = normaliseCwe(finding.cwe);
        if (!cwe || !OURS.has(cwe)) continue;       // out of our scope
        const hit = labels.filter((l) => matches(finding, l));
        if (hit.length === 0) { unlabelled++; continue; }
        for (const label of hit) {
          if (label.is_vulnerable) matched.add(`${record.key}#${label.id}`);
          else trapsTripped.add(`${record.key}#${label.id}`);
        }
      }
    }

    let vulnerable = 0, traps = 0;
    for (const repo of repos) {
      for (const label of repo.labels) {
        label.is_vulnerable ? vulnerable++ : traps++;
      }
    }

    const tp = matched.size;
    const fn = vulnerable - tp;
    const fpTrap = trapsTripped.size;
    const recall = vulnerable ? tp / vulnerable : 0;
    const trapRate = traps ? fpTrap / traps : 0;
    const precision = tp + fpTrap + unlabelled ? tp / (tp + fpTrap + unlabelled) : 0;

    config[name] = {
      vulnerable, traps, tp, fn, fpTrap, unlabelled,
      recall, trapRate, precision,
      f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
    };
  }

  return config;
}

/* ------------------------------------------------------------------ */

async function main() {
  const args = process.argv.slice(2);
  const staticOnly = args.includes("--static-only");
  const dryRun = args.includes("--dry-run");
  const fresh = args.includes("--fresh");

  fs.mkdirSync(OUT, { recursive: true });
  const cachePath = path.join(OUT, "raw.jsonl");
  if (fresh && fs.existsSync(cachePath)) fs.unlinkSync(cachePath);

  const { repos, byFile } = loadGroundTruth();

  const targets = [];
  for (const repo of repos) {
    for (const file of pythonFiles(repo.root)) {
      const rel = path.relative(repo.root, file).replace(/\\/g, "/");
      targets.push({ key: `${repo.id}::${rel}`, file, repo: repo.id, rel });
    }
  }

  const labelled = new Set([...byFile.keys()]);
  const resolvable = targets.filter((t) => labelled.has(t.key)).length;

  let vulnerable = 0, traps = 0;
  for (const repo of repos) {
    for (const l of repo.labels) l.is_vulnerable ? vulnerable++ : traps++;
  }

  console.log(`repos with in-scope labels : ${repos.length}`);
  console.log(`in-scope labels            : ${vulnerable} vulnerabilities, ${traps} traps`);
  console.log(`python files to scan       : ${targets.length}`);
  console.log(`labelled files resolved    : ${resolvable} of ${labelled.size}`);

  if (resolvable < labelled.size) {
    console.log(`\nWARNING: ${labelled.size - resolvable} labelled files were not found on disk.`);
    for (const key of labelled) {
      if (!targets.some((t) => t.key === key)) console.log(`  missing: ${key}`);
    }
  }

  if (dryRun) return;

  const done = new Set();
  if (fs.existsSync(cachePath)) {
    for (const line of fs.readFileSync(cachePath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try { done.add(JSON.parse(line).key); } catch { /* partial line */ }
    }
    if (done.size) console.log(`resuming: ${done.size} files cached`);
  }

  const { initAstAnalyzer, analyzeCode } = require(
    path.join(__dirname, "..", "out", "analyzer", "analyze.js")
  );
  await initAstAnalyzer();

  const pending = targets.filter((t) => !done.has(t.key));
  console.log(`\nscanning ${pending.length} files...\n`);

  const sink = fs.createWriteStream(cachePath, { flags: "a" });
  const started = Date.now();
  let n = 0, failed = 0;

  for (const target of pending) {
    const record = { key: target.key, repo: target.repo, file: target.rel };
    let code = "";
    try { code = fs.readFileSync(target.file, "utf8"); } catch { continue; }

    let findings = [];
    try {
      findings = analyzeCode(code, target.file);
      record.static = findings.map((f) => ({ cwe: f.cweId, line: f.line, rule: f.ruleId }));
    } catch (err) {
      record.static = [];
      record.staticError = String(err.message ?? err);
    }

    if (!staticOnly) {
      try {
        const response = await analyzeWithRetry(code, findings);
        record.model = (response.vulnerabilities ?? []).map((v) => ({
          cwe: v.cwe,
          line: v.start_line,
          end_line: v.end_line,
          fixes: v.fixes ?? [],
        }));
      } catch (err) {
        record.model = [];
        record.error = String(err.message ?? err);
        failed++;
        await sleep(1500);
      }
    } else record.model = [];

    sink.write(JSON.stringify(record) + "\n");
    n++;

    if (n % 20 === 0 || n === pending.length) {
      const elapsed = Date.now() - started;
      const per = elapsed / n;
      console.log(
        `[${n}/${pending.length}] ${(per / 1000).toFixed(1)}s/file  ` +
        `remaining ~${Math.round(((pending.length - n) * per) / 60000)}m` +
        (failed ? `  (${failed} errors)` : "")
      );
    }
  }
  await new Promise((r) => sink.end(r));

  /* ---------------- score ---------------- */

  const records = fs.readFileSync(cachePath, "utf8").split("\n")
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const result = score(records, byFile, repos);

  const pct = (v) => (v * 100).toFixed(1);
  const out = [];
  out.push("\n## RealVuln — real-world Python applications\n");
  out.push(`${repos.length} repositories, ${targets.length} Python files scanned.`);
  out.push(`Ground truth: ${vulnerable} vulnerabilities and ${traps} false-positive traps within the ten CWEs the analyzer covers. Labels are third-party manual review.`);
  out.push("");
  out.push("| Config | Recall | Trap FP rate | Precision | F1 | TP | FN | Traps tripped | Unlabelled findings |");
  out.push("|---|---|---|---|---|---|---|---|---|");
  for (const name of ["static", "hybrid"]) {
    const m = result[name];
    out.push(
      `| ${name === "static" ? "Static" : "Hybrid"} | ${pct(m.recall)}% | ${pct(m.trapRate)}% | ` +
      `${pct(m.precision)}% | ${pct(m.f1)}% | ${m.tp} | ${m.fn} | ${m.fpTrap}/${m.traps} | ${m.unlabelled} |`
    );
  }
  out.push("");
  out.push("Trap FP rate is the share of RealVuln's deliberate false-positive traps that the tool flagged. Unlabelled findings are in-scope detections at locations RealVuln did not label at all; they are counted against precision but reported separately, since a subset may be genuine vulnerabilities the labellers missed.");

  const text = out.join("\n");
  fs.writeFileSync(path.join(OUT, "results.md"), text, "utf8");
  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify(result, null, 2), "utf8");
  console.log(text);
  console.log(`\nwritten to ${OUT}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
