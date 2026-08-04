/**
 * Hybrid benchmark runner: static analyzer vs static + model.
 *
 * Runs every case through the static analyzer, then sends the code plus
 * those findings to the model exactly as the extension does, and records
 * both results. Designed to be started and left alone:
 *
 * - every case is appended to a JSONL cache as soon as it completes, so a
 *   crash or Ctrl+C costs one case, not the whole run
 * - re-running resumes from the cache and skips finished cases
 * - scoring reads the cache, so metrics can be recomputed without inference
 *
 * Usage:
 *   node bench/run.js [options]
 *
 *   --owasp-limit N    cases per OWASP category      (default 0 = all)
 *   --juliet-limit N   files per Juliet CWE group    (default 170)
 *   --max-good N       good functions per Juliet file (default 2)
 *   --endpoint URL     model server                  (default http://localhost:8000)
 *   --out DIR          output directory              (default bench/results)
 *   --static-only      skip the model entirely
 *   --dry-run          build the corpus, print the plan, run nothing
 *   --fresh            ignore any existing cache
 *   --retry-errors     re-run only the cases that previously errored
 *   --no-static-context  send analysis: [] so the model detects unaided
 *   --only GROUP       restrict the corpus to one group (sqli, CWE-190, ...)
 */

const fs = require("fs");
const path = require("path");
const http = require("http");
const https = require("https");
const { URL } = require("url");

const {
  loadTrainingExclusions,
  buildOwaspCases,
  buildJulietCases,
} = require("./corpus");
const { score } = require("./score");

const REPO_ROOT = path.resolve(__dirname, "..", "..");
const OUT_ROOT = path.resolve(__dirname, "..", "out");

const DEFAULTS = {
  owaspRoot: "C:/temp/owasp-benchmark",
  julietRoot: "C:/temp/juliet",
  datasetRoot: path.join(REPO_ROOT, "dataset", "raw"),
  endpoint: "http://localhost:8000",
  owaspLimit: 0,
  julietLimit: 170,
  maxGood: 2,
  out: path.join(__dirname, "results"),
};

/* ------------------------------------------------------------------ */

function parseArgs(argv) {
  const opts = {
    ...DEFAULTS,
    staticOnly: false,
    dryRun: false,
    fresh: false,
    retryErrors: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => argv[++i];

    switch (arg) {
      case "--owasp-limit": opts.owaspLimit = Number(value()); break;
      case "--juliet-limit": opts.julietLimit = Number(value()); break;
      case "--max-good": opts.maxGood = Number(value()); break;
      case "--endpoint": opts.endpoint = value().replace(/\/+$/, ""); break;
      case "--out": opts.out = path.resolve(value()); break;
      case "--owasp-root": opts.owaspRoot = value(); break;
      case "--juliet-root": opts.julietRoot = value(); break;
      case "--static-only": opts.staticOnly = true; break;
      case "--dry-run": opts.dryRun = true; break;
      case "--fresh": opts.fresh = true; break;
      case "--retry-errors": opts.retryErrors = true; break;
      default:
        if (arg.startsWith("--")) {
          console.error(`Unknown option: ${arg}`);
          process.exit(1);
        }
    }
  }
  return opts;
}

/* ------------------------------------------------------------------ *
 * Model client — same contract as src/model/client.ts
 * ------------------------------------------------------------------ */

function analyzeWithModel(code, staticFindings, endpoint) {
  const url = new URL(`${endpoint}/analyze`);
  const body = JSON.stringify({ code, analysis: staticFindings });
  const lib = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) {
            try {
              resolve(JSON.parse(data));
            } catch {
              reject(new Error(`invalid JSON: ${data.slice(0, 160)}`));
            }
          } else {
            reject(new Error(`HTTP ${status}: ${data.slice(0, 160)}`));
          }
        });
      }
    );

    req.setTimeout(300_000, () => req.destroy(new Error("timeout after 300s")));
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * A dropped connection is worth retrying; an HTTP 500 is not.
 *
 * The model is deterministic (do_sample=False), so a 500 caused by the model
 * emitting a response the API cannot validate will reproduce exactly on every
 * attempt. Retrying it would burn ~45s per case for nothing. Connection-level
 * failures are transient — one was observed immediately after a 500, while the
 * server was still recovering — and do recover on a second attempt.
 */
async function analyzeWithRetry(code, findings, endpoint, attempts = 3) {
  let lastError;

  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await analyzeWithModel(code, findings, endpoint);
    } catch (err) {
      lastError = err;
      const message = String(err.message ?? err);
      if (/^HTTP 5\d\d/.test(message) || /^HTTP 4\d\d/.test(message)) throw err;
      if (attempt < attempts) await sleep(2000 * attempt);
    }
  }

  throw lastError;
}

function waitForModel(endpoint) {
  const url = new URL(`${endpoint}/health`);
  const lib = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    const req = lib.get(
      { hostname: url.hostname, port: url.port, path: url.pathname },
      (res) => {
        res.resume();
        res.statusCode === 200
          ? resolve()
          : reject(new Error(`health check returned ${res.statusCode}`));
      }
    );
    req.setTimeout(10_000, () => req.destroy(new Error("health check timed out")));
    req.on("error", reject);
  });
}

/* ------------------------------------------------------------------ */

function formatDuration(ms) {
  const total = Math.round(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  return h > 0 ? `${h}h ${m}m` : m > 0 ? `${m}m ${s}s` : `${s}s`;
}

async function main() {
  const opts = parseArgs(process.argv);
  fs.mkdirSync(opts.out, { recursive: true });

  const cachePath = path.join(opts.out, "raw.jsonl");
  const logPath = path.join(opts.out, "run.log");
  const log = fs.createWriteStream(logPath, { flags: opts.fresh ? "w" : "a" });

  const say = (line) => {
    process.stdout.write(line + "\n");
    log.write(line + "\n");
  };

  say(`\n=== SecureAssist hybrid benchmark — ${new Date().toISOString()} ===`);

  /* ---------------- corpus ---------------- */

  const exclusions = loadTrainingExclusions(opts.datasetRoot);
  say(
    `Training exclusions: ${exclusions.owasp.size} OWASP files, ` +
      `${exclusions.julietFamilies.size} Juliet families`
  );

  const owasp = buildOwaspCases(opts.owaspRoot, exclusions, opts.owaspLimit);
  const juliet = buildJulietCases(
    opts.julietRoot,
    exclusions,
    opts.julietLimit,
    opts.maxGood
  );

  const cases = [...owasp.cases, ...juliet.cases];

  say(
    `Excluded as contaminated: ${owasp.skippedTrained} OWASP cases, ` +
      `${juliet.skippedTrained} Juliet files`
  );
  say(`Corpus: ${cases.length} cases (${owasp.cases.length} OWASP, ${juliet.cases.length} Juliet)`);

  const byGroup = new Map();
  for (const c of cases) {
    const key = `${c.suite}/${c.group}`;
    const entry = byGroup.get(key) ?? { vuln: 0, safe: 0 };
    c.expected ? entry.vuln++ : entry.safe++;
    byGroup.set(key, entry);
  }
  for (const [key, entry] of byGroup) {
    say(`  ${key.padEnd(24)} ${entry.vuln} vulnerable, ${entry.safe} safe`);
  }

  /* ---------------- resume ---------------- */

  const done = new Map();
  if (!opts.fresh && fs.existsSync(cachePath)) {
    for (const line of fs.readFileSync(cachePath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        // --retry-errors drops previously failed cases from the cache so they
        // are attempted again, without repeating the ones that succeeded.
        if (opts.retryErrors && (record.modelError || record.staticError)) {
          done.delete(record.id);
          continue;
        }
        done.set(record.id, record);
      } catch {
        /* truncated final line from an interrupted run — ignore */
      }
    }
    say(`Resuming: ${done.size} cases already cached`);
  } else if (opts.fresh && fs.existsSync(cachePath)) {
    fs.unlinkSync(cachePath);
    say("Starting fresh: previous cache deleted");
  }

  const pending = cases.filter((c) => !done.has(c.id));
  const estimate = opts.staticOnly ? 0 : pending.length * 8000;
  say(
    `Pending: ${pending.length} cases` +
      (opts.staticOnly ? " (static only)" : ` — estimated ${formatDuration(estimate)} at 8s/case`)
  );

  if (opts.dryRun) {
    say("Dry run: nothing executed.");
    log.end();
    return;
  }

  /* ---------------- analyzer ---------------- */

  const { initAstAnalyzer, analyzeCode } = require(
    path.join(OUT_ROOT, "analyzer", "analyze.js")
  );
  await initAstAnalyzer();
  say("Static analyzer ready.");

  if (!opts.staticOnly && pending.length > 0) {
    try {
      await waitForModel(opts.endpoint);
      say(`Model server ready at ${opts.endpoint}.`);
    } catch (err) {
      say(`\nCannot reach the model server at ${opts.endpoint}: ${err.message}`);
      say("Start the container first, or pass --static-only.");
      log.end();
      process.exit(1);
    }
  }

  /* ---------------- run ---------------- */

  const sink = fs.createWriteStream(cachePath, { flags: "a" });
  let stopping = false;
  process.on("SIGINT", () => {
    say("\nInterrupted — finishing the current case, progress is saved.");
    stopping = true;
  });

  const started = Date.now();
  let completed = 0;
  let failed = 0;

  for (const testCase of pending) {
    if (stopping) break;

    const caseStart = Date.now();
    const record = {
      id: testCase.id,
      suite: testCase.suite,
      group: testCase.group,
      targetCwe: testCase.targetCwe,
      accept: testCase.accept,
      expected: testCase.expected,
    };

    // The static result is recorded even when the model call later fails, so
    // a server-side error never silently removes a case from the static column.
    let findings = [];
    try {
      findings = analyzeCode(testCase.code, testCase.fileName);
      record.static = findings.map((f) => ({
        cwe: f.cweId,
        line: f.line,
        rule: f.ruleId,
      }));
    } catch (err) {
      record.staticError = String(err.message ?? err);
      record.static = [];
    }

    if (opts.staticOnly) {
      record.model = null;
    } else {
      try {
        // The full Finding objects, exactly as src/model/client.ts sends them.
        const response = await analyzeWithRetry(
          testCase.code,
          findings,
          opts.endpoint
        );
        record.model = (response.vulnerabilities ?? []).map((v) => ({
          cwe: v.cwe,
          start_line: v.start_line,
          end_line: v.end_line,
          fixes: (v.fixes ?? []).length,
        }));
      } catch (err) {
        record.model = null;
        record.modelError = String(err.message ?? err);
        failed++;
        // Give the server a moment; a reset was seen right after a 500.
        await sleep(2000);
      }
    }

    record.ms = Date.now() - caseStart;
    sink.write(JSON.stringify(record) + "\n");
    completed++;

    const elapsed = Date.now() - started;
    const perCase = elapsed / completed;
    const remaining = (pending.length - completed) * perCase;

    if (completed % 10 === 0 || completed === pending.length) {
      say(
        `[${completed}/${pending.length}] ` +
          `${(perCase / 1000).toFixed(1)}s/case  ` +
          `elapsed ${formatDuration(elapsed)}  ` +
          `remaining ~${formatDuration(remaining)}` +
          (failed ? `  (${failed} errors)` : "")
      );
    }
  }

  await new Promise((resolve) => sink.end(resolve));

  say(
    `\nRun ${stopping ? "interrupted" : "complete"}: ` +
      `${completed} cases in ${formatDuration(Date.now() - started)}` +
      (failed ? `, ${failed} errors` : "")
  );

  /* ---------------- score ---------------- */

  const report = score(cachePath, { staticOnly: opts.staticOnly });
  fs.writeFileSync(path.join(opts.out, "results.md"), report.markdown, "utf8");
  fs.writeFileSync(
    path.join(opts.out, "results.json"),
    JSON.stringify(report.data, null, 2),
    "utf8"
  );
  fs.writeFileSync(path.join(opts.out, "results.csv"), report.csv, "utf8");

  say(report.markdown);
  say(`\nWritten to:`);
  say(`  ${path.join(opts.out, "results.md")}`);
  say(`  ${path.join(opts.out, "results.csv")}`);
  say(`  ${path.join(opts.out, "results.json")}`);
  say(`  ${cachePath}  (raw cache — re-score without re-running)`);

  log.end();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
