/**
 * Scoring for the hybrid benchmark.
 *
 * Reads the JSONL cache written by run.js and produces the comparison
 * table. Kept separate from the runner so metrics can be recomputed, or the
 * acceptance sets revised, without repeating six hours of inference.
 *
 * Usage:  node bench/score.js [resultsDir]
 */

const fs = require("fs");
const path = require("path");

/** Model output is not guaranteed to be well formed; normalise what we can. */
function normaliseCwe(value) {
  if (typeof value !== "string") return undefined;
  const match = value.match(/(\d{1,4})/);
  return match ? `CWE-${match[1]}` : undefined;
}

function detected(reported, accept) {
  const set = new Set(accept);
  return reported.some((r) => {
    const cwe = normaliseCwe(r.cwe);
    return cwe !== undefined && set.has(cwe);
  });
}

function emptyCell() {
  return { tp: 0, fn: 0, fp: 0, tn: 0 };
}

function tally(cell, expected, hit) {
  if (expected) hit ? cell.tp++ : cell.fn++;
  else hit ? cell.fp++ : cell.tn++;
}

function derive(cell) {
  const positives = cell.tp + cell.fn;
  const negatives = cell.fp + cell.tn;
  const tpr = positives ? cell.tp / positives : 0;
  const fpr = negatives ? cell.fp / negatives : 0;
  const precision = cell.tp + cell.fp ? cell.tp / (cell.tp + cell.fp) : 0;
  const f1 = precision + tpr ? (2 * precision * tpr) / (precision + tpr) : 0;
  return {
    ...cell,
    tpr,
    fpr,
    youden: tpr - fpr,
    precision,
    f1,
  };
}

const pct = (v) => (v * 100).toFixed(1);

function score(cachePath, options = {}) {
  const staticOnly = options.staticOnly === true;

  const records = fs
    .readFileSync(cachePath, "utf8")
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return undefined;
      }
    })
    .filter(Boolean);

  // A resumed run can append a case twice; last write wins.
  const unique = new Map();
  for (const record of records) unique.set(record.id, record);

  const groups = new Map();
  const configs = staticOnly ? ["static"] : ["static", "model", "hybrid"];
  let modelTotalMs = 0;
  let modelCases = 0;

  const gained = [];
  const introduced = [];

  /*
   * Cases where the model call failed are dropped from every column, not just
   * the model ones. Scoring static on cases the model never saw would put the
   * two configurations on different case sets and make the comparison
   * meaningless. The count and causes are reported below so the loss is visible.
   */
  const errorCauses = new Map();
  let excluded = 0;

  for (const record of unique.values()) {
    if (record.staticError) {
      excluded++;
      errorCauses.set("static analyzer", (errorCauses.get("static analyzer") ?? 0) + 1);
      continue;
    }
    if (!staticOnly && record.modelError) {
      excluded++;
      const cause = /^HTTP 5\d\d/.test(record.modelError)
        ? "model server rejected its own output (HTTP 500)"
        : /timeout/i.test(record.modelError)
          ? "inference timeout"
          : "connection error";
      errorCauses.set(cause, (errorCauses.get(cause) ?? 0) + 1);
      continue;
    }

    const key = `${record.suite}/${record.group}`;
    if (!groups.has(key)) {
      const cells = {};
      for (const config of configs) cells[config] = emptyCell();
      groups.set(key, cells);
    }
    const cells = groups.get(key);

    const staticHit = detected(record.static ?? [], record.accept);
    tally(cells.static, record.expected, staticHit);

    if (!staticOnly) {
      const modelHit = detected(record.model ?? [], record.accept);
      const hybridHit = staticHit || modelHit;

      tally(cells.model, record.expected, modelHit);
      tally(cells.hybrid, record.expected, hybridHit);

      if (typeof record.ms === "number") {
        modelTotalMs += record.ms;
        modelCases++;
      }

      // What the model actually changed, case by case.
      if (record.expected && !staticHit && modelHit) gained.push(record.id);
      if (!record.expected && !staticHit && modelHit) introduced.push(record.id);
    }
  }

  /* ---------------- aggregate ---------------- */

  const rows = [];
  const totals = {};
  for (const config of configs) totals[config] = emptyCell();

  for (const [group, cells] of [...groups.entries()].sort()) {
    const row = { group, configs: {} };
    for (const config of configs) {
      row.configs[config] = derive(cells[config]);
      for (const field of ["tp", "fn", "fp", "tn"]) {
        totals[config][field] += cells[config][field];
      }
    }
    rows.push(row);
  }

  const overall = {};
  for (const config of configs) overall[config] = derive(totals[config]);

  /* ---------------- markdown ---------------- */

  const label = { static: "Static", model: "Model", hybrid: "Hybrid" };
  const out = [];

  out.push("\n## Benchmark results\n");
  out.push(`Cases scored: ${unique.size - excluded} of ${unique.size}`);
  if (excluded) {
    out.push("");
    out.push(
      `${excluded} cases excluded from all columns so every configuration is ` +
        `scored on the same set:`
    );
    for (const [cause, count] of [...errorCauses.entries()].sort((a, b) => b[1] - a[1])) {
      out.push(`  - ${count} — ${cause}`);
    }
  }
  if (modelCases) {
    out.push(
      `Mean inference time: ${(modelTotalMs / modelCases / 1000).toFixed(1)}s per case\n`
    );
  }

  out.push("");
  out.push("| Suite / category | Config | TPR | FPR | Youden | Precision | F1 | TP | FN | FP | TN |");
  out.push("|---|---|---|---|---|---|---|---|---|---|---|");

  const emit = (name, configsMap) => {
    for (const config of configs) {
      const m = configsMap[config];
      out.push(
        `| ${name} | ${label[config]} | ${pct(m.tpr)}% | ${pct(m.fpr)}% | ` +
          `${(m.youden * 100).toFixed(1)} | ${pct(m.precision)}% | ${pct(m.f1)}% | ` +
          `${m.tp} | ${m.fn} | ${m.fp} | ${m.tn} |`
      );
      name = "";
    }
  };

  for (const row of rows) emit(row.group, row.configs);
  emit("**Overall**", overall);

  if (!staticOnly) {
    out.push("");
    out.push("### What the model changed");
    out.push("");
    out.push(
      `- Recovered ${gained.length} vulnerable cases the static analyzer missed`
    );
    out.push(
      `- Introduced ${introduced.length} false positives on safe cases the static analyzer got right`
    );
    const delta = (overall.hybrid.youden - overall.static.youden) * 100;
    out.push(
      `- Net Youden change: ${delta >= 0 ? "+" : ""}${delta.toFixed(1)} points ` +
        `(${(overall.static.youden * 100).toFixed(1)} → ${(overall.hybrid.youden * 100).toFixed(1)})`
    );

    out.push("");
    out.push(
      "The Model column is reported for completeness only. The model receives " +
        "the static findings as input, exactly as it does in the extension, so " +
        "it is not an independent detector and must not be read as one."
    );
  }

  out.push("");
  out.push("### Method notes");
  out.push("");
  out.push(
    "- Test cases whose family appears in the model's fine-tuning set are excluded."
  );
  out.push(
    "- Comments are stripped and verdict-bearing identifiers renamed, so neither " +
      "configuration can read the answer from Juliet's `POTENTIAL FLAW` / `FIX` " +
      "annotations or from the OWASP servlet path."
  );
  out.push(
    "- Both configurations receive byte-identical input; the only difference is " +
      "whether the model is consulted."
  );
  out.push(
    "- Juliet is scored per function (`bad` positive, `goodG2B` / `goodB2G` negative) " +
      "because each file contains both the flaw and its fix."
  );
  out.push(
    "- A detection counts when the reported CWE is in the case's accept set; " +
      "CWE-787 also accepts CWE-190 (our rules report size arithmetic that way) " +
      "and CWE-327/CWE-328 are accepted interchangeably."
  );

  /* ---------------- csv ---------------- */

  const csv = ["suite_category,config,tpr,fpr,youden,precision,f1,tp,fn,fp,tn"];
  const csvRow = (name, m, config) =>
    `${name},${config},${m.tpr.toFixed(4)},${m.fpr.toFixed(4)},${m.youden.toFixed(4)},` +
    `${m.precision.toFixed(4)},${m.f1.toFixed(4)},${m.tp},${m.fn},${m.fp},${m.tn}`;

  for (const row of rows) {
    for (const config of configs) {
      csv.push(csvRow(row.group, row.configs[config], config));
    }
  }
  for (const config of configs) csv.push(csvRow("overall", overall[config], config));

  return {
    markdown: out.join("\n"),
    csv: csv.join("\n") + "\n",
    data: {
      generated: new Date().toISOString(),
      total: unique.size,
      scored: unique.size - excluded,
      excluded,
      errorCauses: Object.fromEntries(errorCauses),
      meanInferenceMs: modelCases ? modelTotalMs / modelCases : null,
      groups: rows,
      overall,
      modelGained: gained,
      modelIntroduced: introduced,
    },
  };
}

module.exports = { score };

if (require.main === module) {
  const dir = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.join(__dirname, "results");
  const cache = path.join(dir, "raw.jsonl");

  if (!fs.existsSync(cache)) {
    console.error(`No cache at ${cache}. Run bench/run.js first.`);
    process.exit(1);
  }

  const report = score(cache);
  fs.writeFileSync(path.join(dir, "results.md"), report.markdown, "utf8");
  fs.writeFileSync(path.join(dir, "results.csv"), report.csv, "utf8");
  fs.writeFileSync(
    path.join(dir, "results.json"),
    JSON.stringify(report.data, null, 2),
    "utf8"
  );
  console.log(report.markdown);
}
