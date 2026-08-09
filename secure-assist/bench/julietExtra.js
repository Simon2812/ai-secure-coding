/**
 * Juliet — the C CWEs the first run did not cover.
 *
 * The original Juliet run measured CWE-190, CWE-416 and CWE-787: the three
 * memory-safety categories, and the hardest three the analyzer implements for
 * C. It supports five more — command injection, hard-coded passwords and keys,
 * broken cryptography and reversible hashes — and Juliet has test suites for
 * all of them. This runs those, so the C column reflects the whole of the
 * analyzer's C coverage rather than its most difficult third.
 *
 * Same method as the first run, so the numbers are comparable:
 *   - test-case families present in the model's training corpus are excluded
 *   - comments are stripped and verdict-bearing identifiers renamed, so
 *     neither configuration can read the answer out of Juliet's annotations
 *   - each file is split into functions: bad is a positive case, goodG2B and
 *     goodB2G are negative cases
 *   - a case whose model call fails is dropped from both columns
 *
 * Resumable: every case is written to the cache as it completes, so re-running
 * the same command picks up where it stopped.
 *
 *   node bench/julietExtra.js                 run everything, default caps
 *   node bench/julietExtra.js --dry-run       show the plan, run nothing
 *   node bench/julietExtra.js --static-only   skip the model (seconds)
 *   node bench/julietExtra.js --cmdi-limit 60 fewer command-injection files
 *   node bench/julietExtra.js --fresh         ignore the cache and start over
 */

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const { loadTrainingExclusions, stripComments } = require("./corpus");

const JULIET = "C:/temp/juliet/testcases";
const DATASET = path.resolve(__dirname, "..", "..", "dataset", "raw");
const OUT = path.join(__dirname, "results-juliet-extra");
const ENDPOINT = "http://localhost:8000";

/**
 * The five CWEs missing from the first Juliet run.
 *
 * CWE-78 has 1,900 intra-procedural files against a few dozen for the others,
 * so it is capped by default — left uncapped it would be 85% of the run and
 * would take most of a night for no extra information.
 */
const GROUPS = {
  "CWE-78": { dir: "CWE78_OS_Command_Injection", accept: ["CWE-78"], limit: 120 },
  "CWE-259": { dir: "CWE259_Hard_Coded_Password", accept: ["CWE-259", "CWE-321"], limit: 0 },
  "CWE-321": { dir: "CWE321_Hard_Coded_Cryptographic_Key", accept: ["CWE-321", "CWE-259"], limit: 0 },
  "CWE-327": { dir: "CWE327_Use_Broken_Crypto", accept: ["CWE-327", "CWE-328"], limit: 0 },
  "CWE-328": { dir: "CWE328_Reversible_One_Way_Hash", accept: ["CWE-328", "CWE-327"], limit: 0 },
};

/** Flow variants 01-21 keep the whole flow inside one function. */
const INTRA_PROCEDURAL = /_(0[1-9]|1[0-9]|2[01])\.c$/;

/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const o = { dryRun: false, staticOnly: false, fresh: false, endpoint: ENDPOINT, limits: {} };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--dry-run") o.dryRun = true;
    else if (a === "--static-only") o.staticOnly = true;
    else if (a === "--fresh") o.fresh = true;
    else if (a === "--endpoint") o.endpoint = argv[++i].replace(/\/+$/, "");
    else if (a === "--cmdi-limit") o.limits["CWE-78"] = Number(argv[++i]);
    else if (a.startsWith("--")) { console.error(`unknown option: ${a}`); process.exit(1); }
  }
  return o;
}

/** "CWE78_OS_Command_Injection__char_console_execl_01" -> family without the variant. */
const familyOf = (base) => base.replace(/_\d{2}[a-z]?$/, "");

function collect(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    if (e.isDirectory()) collect(full, out);
    else if (e.name.endsWith(".c")) out.push(full);
  }
  return out;
}

/** Round-robin across families so a capped sample still covers many sinks. */
function spreadByFamily(files) {
  const families = new Map();
  for (const f of files) {
    const key = familyOf(path.basename(f, ".c"));
    if (!families.has(key)) families.set(key, []);
    families.get(key).push(f);
  }
  const buckets = [...families.values()];
  const out = [];
  for (let i = 0; out.length < files.length; i++) {
    let moved = false;
    for (const b of buckets) if (i < b.length) { out.push(b[i]); moved = true; }
    if (!moved) break;
  }
  return out;
}

function extractFunction(code, start) {
  const open = code.indexOf("{", start);
  if (open === -1) return undefined;
  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === "{") depth++;
    else if (code[i] === "}") { depth--; if (depth === 0) return code.slice(start, i + 1); }
  }
  return undefined;
}

/**
 * Split a Juliet file into scoring units.
 *
 * Each file holds the flaw and its fixes side by side, so the file as a whole
 * has no single verdict. Function names announce the answer, so each extracted
 * function is renamed to the same neutral symbol.
 */
function splitFunctions(code, maxGood = 2) {
  const out = [];
  const signature = /(?:static\s+)?void\s+([A-Za-z_]\w*)\s*\(\s*(?:void\s*)?\)\s*\{/g;
  let m, good = 0;

  while ((m = signature.exec(code)) !== null) {
    const name = m[1];
    const isBad = /_bad$/.test(name);
    const isGood = /^good/.test(name);
    if (!isBad && !isGood) continue;
    if (name === "good") continue;            // dispatcher
    if (isGood && good >= maxGood) continue;

    const body = extractFunction(code, m.index);
    if (!body) continue;

    let kind = "bad";
    if (isGood) {
      kind = name.includes("G2B") ? "goodG2B" : name.includes("B2G") ? "goodB2G" : "good";
      good++;
    }
    out.push({
      kind,
      ordinal: out.filter((r) => r.kind === kind).length + 1,
      expected: isBad,
      code: body.split(name).join("process_data"),
    });
  }
  return out;
}

/* ------------------------------------------------------------------ */

function analyzeWithModel(code, findings, endpoint) {
  const url = new URL(`${endpoint}/analyze`);
  const body = JSON.stringify({ code, analysis: findings });
  const lib = url.protocol === "https:" ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      { hostname: url.hostname, port: url.port, path: url.pathname, method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          const s = res.statusCode ?? 0;
          if (s >= 200 && s < 300) {
            try { resolve(JSON.parse(data)); }
            catch { reject(new Error(`invalid JSON: ${data.slice(0, 160)}`)); }
          } else reject(new Error(`HTTP ${s}: ${data.slice(0, 160)}`));
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

/** Retry dropped connections; an HTTP error is deterministic, so do not. */
async function analyzeWithRetry(code, findings, endpoint, attempts = 3) {
  let last;
  for (let i = 1; i <= attempts; i++) {
    try { return await analyzeWithModel(code, findings, endpoint); }
    catch (err) {
      last = err;
      if (/^HTTP [45]\d\d/.test(String(err.message))) throw err;
      if (i < attempts) await sleep(2000 * i);
    }
  }
  throw last;
}

/* ------------------------------------------------------------------ */

const normalise = (v) => {
  const m = typeof v === "string" && v.match(/(\d{1,4})/);
  return m ? `CWE-${m[1]}` : null;
};
const reports = (list, accept) =>
  (list ?? []).some((x) => accept.includes(normalise(x.cwe)));

function score(records, staticOnly) {
  const configs = staticOnly ? ["static"] : ["static", "model", "hybrid"];
  const groups = new Map();
  const totals = {};
  for (const c of configs) totals[c] = { tp: 0, fn: 0, fp: 0, tn: 0 };
  let excluded = 0;

  for (const r of records) {
    if (r.staticError || (!staticOnly && r.modelError)) { excluded++; continue; }
    if (!groups.has(r.group)) {
      groups.set(r.group, Object.fromEntries(configs.map((c) => [c, { tp: 0, fn: 0, fp: 0, tn: 0 }])));
    }
    const g = groups.get(r.group);
    const s = reports(r.static, r.accept);
    const m = staticOnly ? false : reports(r.model, r.accept);
    const tally = (cell, hit) => {
      if (r.expected) hit ? cell.tp++ : cell.fn++;
      else hit ? cell.fp++ : cell.tn++;
    };
    tally(g.static, s); tally(totals.static, s);
    if (!staticOnly) {
      tally(g.model, m); tally(totals.model, m);
      tally(g.hybrid, s || m); tally(totals.hybrid, s || m);
    }
  }

  const metrics = (c) => {
    const pos = c.tp + c.fn, neg = c.fp + c.tn;
    const recall = pos ? c.tp / pos : 0;
    const fpr = neg ? c.fp / neg : 0;
    const precision = c.tp + c.fp ? c.tp / (c.tp + c.fp) : 0;
    const f = (b) => {
      const b2 = b * b;
      return b2 * precision + recall ? ((1 + b2) * precision * recall) / (b2 * precision + recall) : 0;
    };
    return { ...c, recall, fpr, precision, youden: recall - fpr, f1: f(1), f3: f(3) };
  };

  const pct = (v) => `${(v * 100).toFixed(1)}%`;
  const out = [];
  out.push("\n## Juliet — additional C weaknesses\n");
  out.push(`${records.length - excluded} cases scored${excluded ? `, ${excluded} excluded (model error)` : ""}.`);
  out.push("");
  out.push("| Category (CWE) | Config | Recall | Precision | FP rate | Youden | F1 | F3 | TP | FN | FP | TN |");
  out.push("|---|---|---|---|---|---|---|---|---|---|---|---|");

  const label = { static: "Static", model: "Model", hybrid: "Hybrid" };
  const row = (name, cfg, m) =>
    `| ${name} | ${label[cfg]} | ${pct(m.recall)} | ${pct(m.precision)} | ${pct(m.fpr)} | ` +
    `${(m.youden * 100).toFixed(1)} | ${(m.f1 * 100).toFixed(1)} | ${(m.f3 * 100).toFixed(1)} | ` +
    `${m.tp} | ${m.fn} | ${m.fp} | ${m.tn} |`;

  for (const [group, cells] of [...groups.entries()].sort()) {
    let name = group;
    for (const c of configs) { out.push(row(name, c, metrics(cells[c]))); name = ""; }
  }
  let name = "**ALL**";
  for (const c of configs) { out.push(row(name, c, metrics(totals[c]))); name = ""; }

  out.push("");
  out.push("These are the C weaknesses absent from the first Juliet run, which covered CWE-190, CWE-416 and CWE-787. Method is identical: training-contaminated families excluded, comments and verdict-bearing identifiers removed, scored per function, failed cases dropped from every column.");
  return out.join("\n");
}

/* ------------------------------------------------------------------ */

async function main() {
  const opts = parseArgs(process.argv);
  fs.mkdirSync(OUT, { recursive: true });
  const cachePath = path.join(OUT, "raw.jsonl");
  if (opts.fresh && fs.existsSync(cachePath)) fs.unlinkSync(cachePath);

  const exclusions = loadTrainingExclusions(DATASET);

  const cases = [];
  const summary = [];

  for (const [cwe, spec] of Object.entries(GROUPS)) {
    const root = path.join(JULIET, spec.dir);
    if (!fs.existsSync(root)) { summary.push(`  ${cwe.padEnd(9)} directory missing — skipped`); continue; }

    const all = collect(root).filter((f) => INTRA_PROCEDURAL.test(path.basename(f)));
    const clean = [];
    let contaminated = 0;
    for (const f of all) {
      if (exclusions.julietFamilies.has(familyOf(path.basename(f, ".c")))) { contaminated++; continue; }
      clean.push(f);
    }

    const limit = opts.limits[cwe] ?? spec.limit;
    const chosen = limit > 0 ? spreadByFamily(clean).slice(0, limit) : spreadByFamily(clean);

    let made = 0;
    for (const file of chosen) {
      const base = path.basename(file, ".c");
      const code = stripComments(fs.readFileSync(file, "utf8"));
      for (const fn of splitFunctions(code)) {
        cases.push({
          id: `juliet2/${cwe}/${base}#${fn.kind}${fn.ordinal}`,
          group: cwe,
          accept: spec.accept,
          expected: fn.expected,
          fileName: `${base}.c`,
          code: fn.code,
        });
        made++;
      }
    }

    summary.push(
      `  ${cwe.padEnd(9)} ${String(all.length).padStart(5)} files, ` +
      `${String(contaminated).padStart(4)} contaminated, ${String(chosen.length).padStart(4)} used` +
      `${limit > 0 ? ` (capped at ${limit})` : ""} -> ${made} cases`
    );
  }

  console.log(`\n=== Juliet extra CWEs — ${new Date().toISOString()} ===`);
  console.log(`Training exclusions: ${exclusions.julietFamilies.size} Juliet families\n`);
  summary.forEach((s) => console.log(s));

  const vuln = cases.filter((c) => c.expected).length;
  console.log(`\ntotal: ${cases.length} cases (${vuln} vulnerable, ${cases.length - vuln} safe)`);

  const done = new Map();
  if (fs.existsSync(cachePath)) {
    for (const line of fs.readFileSync(cachePath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try { const r = JSON.parse(line); done.set(r.id, r); } catch { /* partial line */ }
    }
    if (done.size) console.log(`resuming: ${done.size} already cached`);
  }

  const pending = cases.filter((c) => !done.has(c.id));
  console.log(
    `pending: ${pending.length}` +
    (opts.staticOnly ? " (static only)" : ` — roughly ${Math.round((pending.length * 6) / 60)} minutes at 6s/case`)
  );

  if (opts.dryRun) { console.log("\nDry run: nothing executed."); return; }

  const { initAstAnalyzer, analyzeCode } = require(
    path.join(__dirname, "..", "out", "analyzer", "analyze.js")
  );
  await initAstAnalyzer();
  console.log("\nStatic analyzer ready.");

  if (!opts.staticOnly && pending.length) {
    try {
      await new Promise((resolve, reject) => {
        const u = new URL(`${opts.endpoint}/health`);
        const req = http.get({ hostname: u.hostname, port: u.port, path: u.pathname }, (res) => {
          res.resume();
          res.statusCode === 200 ? resolve() : reject(new Error(`health ${res.statusCode}`));
        });
        req.setTimeout(10_000, () => req.destroy(new Error("health check timed out")));
        req.on("error", reject);
      });
      console.log(`Model server ready at ${opts.endpoint}.\n`);
    } catch (err) {
      console.error(`\nCannot reach the model server at ${opts.endpoint}: ${err.message}`);
      console.error("Start the container, or pass --static-only.");
      process.exit(1);
    }
  }

  const sink = fs.createWriteStream(cachePath, { flags: "a" });
  let stopping = false;
  process.on("SIGINT", () => { console.log("\nInterrupted — progress is saved."); stopping = true; });

  const started = Date.now();
  let n = 0, failed = 0;

  for (const c of pending) {
    if (stopping) break;
    const record = { id: c.id, group: c.group, accept: c.accept, expected: c.expected };

    let findings = [];
    try {
      findings = analyzeCode(c.code, c.fileName);
      record.static = findings.map((f) => ({ cwe: f.cweId, line: f.line, rule: f.ruleId }));
    } catch (err) {
      record.static = [];
      record.staticError = String(err.message ?? err);
    }

    if (opts.staticOnly) record.model = null;
    else {
      try {
        const res = await analyzeWithRetry(c.code, findings, opts.endpoint);
        record.model = (res.vulnerabilities ?? []).map((v) => ({
          cwe: v.cwe, line: v.start_line, fixes: (v.fixes ?? []).length,
        }));
      } catch (err) {
        record.model = null;
        record.modelError = String(err.message ?? err);
        failed++;
        await sleep(1500);
      }
    }

    sink.write(JSON.stringify(record) + "\n");
    n++;

    if (n % 20 === 0 || n === pending.length) {
      const per = (Date.now() - started) / n;
      console.log(
        `[${n}/${pending.length}] ${(per / 1000).toFixed(1)}s/case  ` +
        `remaining ~${Math.round(((pending.length - n) * per) / 60000)}m` +
        (failed ? `  (${failed} errors)` : "")
      );
    }
  }
  await new Promise((r) => sink.end(r));

  const records = fs.readFileSync(cachePath, "utf8").split("\n")
    .filter((l) => l.trim())
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);

  const unique = new Map();
  for (const r of records) unique.set(r.id, r);

  const report = score([...unique.values()], opts.staticOnly);
  fs.writeFileSync(path.join(OUT, "results.md"), report, "utf8");
  console.log(report);
  console.log(`\nwritten to ${path.join(OUT, "results.md")}`);
  console.log(`cache: ${cachePath}  (re-score without re-running)`);
}

main().catch((e) => { console.error(e); process.exit(1); });
