/**
 * False-positive provenance analysis for the OWASP taint categories.
 *
 * The headline FP rate on OWASP is high while the measured rate on real code
 * is 0%. This script establishes why, by classifying the sanitisation
 * mechanism of every "safe" case the tool flagged, and quoting a
 * representative example of each mechanism.
 *
 * Reads the benchmark cache; runs no inference. Safe to run mid-run and
 * re-run when the benchmark finishes.
 *
 *   node bench/fpAnalysis.js [resultsDir] > fp-analysis.md
 */

const fs = require("fs");
const path = require("path");

const OWASP_SRC =
  "C:/temp/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode/";

/** Categories whose findings depend on taint flow, so an FP means the flow was misjudged. */
const TAINT_CATEGORIES = {
  sqli: "CWE-89",
  cmdi: "CWE-78",
  pathtraver: "CWE-22",
};

/**
 * Sanitisation mechanisms OWASP uses in its "safe" variants.
 *
 * Order matters: reflection is checked first because a reflective case may
 * also mention a collection, and the reflection is what defeats the analysis.
 */
const MECHANISMS = [
  {
    id: "reflection",
    label: "Reflection",
    why: "The value passes through a reflective call, so the taint is only traceable by resolving the reflection target.",
    test: (s) => /reflection|doSomething\s*\(|getMethod|invoke\s*\(/.test(s),
  },
  {
    id: "collection",
    label: "Collection key indirection",
    why: "The tainted value is stored in a map or list under one key and read back under another.",
    test: (s) =>
      /HashMap|ArrayList|LinkedList|valuesList|\.put\s*\(|\.remove\s*\(\s*\d/.test(s),
  },
  {
    id: "switch-const",
    label: "Switch on a folded constant",
    why: "The branch is selected by a compile-time-constant expression, so the tainted arm is unreachable.",
    test: (s) => /switch\s*\(/.test(s),
  },
  {
    id: "dead-branch",
    label: "Always-taken arithmetic branch",
    why: "A condition over integer literals is always true, so the tainted assignment never executes.",
    test: (s) =>
      /\d+\s*[\*\+\-\/]\s*\d+/.test(s) && /\bif\s*\(|\?/.test(s),
  },
  {
    id: "encoding",
    label: "Encoding round-trip",
    why: "The value is encoded and decoded, leaving it unchanged but obscuring the flow.",
    test: (s) => /Base64|URLDecoder|URLEncoder|getBytes\s*\(/.test(s),
  },
  {
    id: "string-surgery",
    label: "String reconstruction",
    why: "The value is taken apart and rebuilt via StringBuilder or substring operations.",
    test: (s) => /StringBuilder|substring|\.reverse\s*\(|toCharArray/.test(s),
  },
];

const SINKS =
  /String sql|java\.io\.File|Runtime\.getRuntime|ProcessBuilder|FileInputStream|FileOutputStream/;

function normaliseCwe(value) {
  if (typeof value !== "string") return undefined;
  const m = value.match(/(\d{1,4})/);
  return m ? `CWE-${m[1]}` : undefined;
}

const reports = (findings, cwe) =>
  (findings ?? []).some((f) => normaliseCwe(f.cwe) === cwe);

/**
 * Pull out the region between the tainted read and the sink — the part that
 * decides whether the case is actually exploitable.
 */
function sanitisationSegment(source) {
  const start = source.indexOf("String bar");
  if (start === -1) return source.slice(0, 1200);

  const rest = source.slice(start);
  const sink = rest.search(SINKS);
  return sink > 0 ? rest.slice(0, sink) : rest.slice(0, 1200);
}

function classify(segment) {
  for (const mechanism of MECHANISMS) {
    if (mechanism.test(segment)) return mechanism;
  }
  return { id: "unclassified", label: "Unclassified", why: "" };
}

function tidy(segment) {
  return segment
    .split("\n")
    .map((line) => line.replace(/^ {8}/, ""))
    .join("\n")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

function main() {
  const dir = process.argv[2]
    ? path.resolve(process.argv[2])
    : path.join(__dirname, "results");
  const cache = path.join(dir, "raw.jsonl");

  const records = new Map();
  for (const line of fs.readFileSync(cache, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const record = JSON.parse(line);
      records.set(record.id, record);
    } catch {
      /* interrupted final line */
    }
  }

  const out = [];
  out.push("# Where the OWASP false positives come from");
  out.push("");
  out.push(
    "Every OWASP case the tool flags as vulnerable but the benchmark labels safe, " +
      "classified by the mechanism that makes it safe. Generated from the benchmark " +
      "cache; no inference involved."
  );

  const examples = new Map();
  const grandTotal = { flagged: 0, safe: 0 };
  const grandTally = new Map();

  for (const [category, cwe] of Object.entries(TAINT_CATEGORIES)) {
    const safe = [...records.values()].filter(
      (r) => r.group === category && !r.modelError && !r.expected
    );
    const flagged = safe.filter(
      (r) => reports(r.static, cwe) || reports(r.model, cwe)
    );
    if (safe.length === 0) continue;

    grandTotal.safe += safe.length;
    grandTotal.flagged += flagged.length;

    const tally = new Map();

    for (const record of flagged) {
      const name = record.id.split("/")[1];
      const file = path.join(OWASP_SRC, `${name}.java`);
      if (!fs.existsSync(file)) continue;

      const segment = sanitisationSegment(fs.readFileSync(file, "utf8"));
      const mechanism = classify(segment);

      tally.set(mechanism.id, (tally.get(mechanism.id) ?? 0) + 1);
      grandTally.set(mechanism.id, (grandTally.get(mechanism.id) ?? 0) + 1);

      if (!examples.has(mechanism.id)) {
        examples.set(mechanism.id, { mechanism, name, category, code: tidy(segment) });
      }
    }

    out.push("");
    out.push(`## ${category} (${cwe})`);
    out.push("");
    out.push(
      `${flagged.length} of ${safe.length} safe cases flagged ` +
        `(${((flagged.length / safe.length) * 100).toFixed(1)}%).`
    );
    out.push("");
    out.push("| Mechanism | Cases | Share |");
    out.push("|---|---|---|");

    const total = [...tally.values()].reduce((a, b) => a + b, 0) || 1;
    for (const [id, count] of [...tally.entries()].sort((a, b) => b[1] - a[1])) {
      const label =
        MECHANISMS.find((m) => m.id === id)?.label ?? "Unclassified";
      out.push(`| ${label} | ${count} | ${((count / total) * 100).toFixed(0)}% |`);
    }
  }

  out.push("");
  out.push("## Combined");
  out.push("");
  out.push(
    `${grandTotal.flagged} of ${grandTotal.safe} safe cases across the three ` +
      `taint categories were flagged.`
  );
  out.push("");
  out.push("| Mechanism | Cases | Share |");
  out.push("|---|---|---|");
  const gtot = [...grandTally.values()].reduce((a, b) => a + b, 0) || 1;
  for (const [id, count] of [...grandTally.entries()].sort((a, b) => b[1] - a[1])) {
    const label = MECHANISMS.find((m) => m.id === id)?.label ?? "Unclassified";
    out.push(`| ${label} | ${count} | ${((count / gtot) * 100).toFixed(0)}% |`);
  }

  out.push("");
  out.push("## Representative cases");
  out.push("");
  out.push(
    "One example per mechanism, quoted verbatim. In each, `param` is attacker-controlled " +
      "and `bar` is what reaches the sink."
  );

  for (const { mechanism, name, category, code } of examples.values()) {
    out.push("");
    out.push(`### ${mechanism.label} — \`${name}\` (${category})`);
    if (mechanism.why) {
      out.push("");
      out.push(mechanism.why);
    }
    out.push("");
    out.push("```java");
    out.push(code);
    out.push("```");
  }

  console.log(out.join("\n"));
}

main();
