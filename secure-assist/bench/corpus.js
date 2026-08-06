/**
 * Benchmark corpus construction.
 *
 * Responsibilities:
 * - locate OWASP Benchmark and Juliet test cases
 * - exclude anything whose test-case family appears in our training set
 * - sanitise the source so the model cannot read the answer out of a comment
 * - split Juliet files into per-function cases (bad / goodG2B / goodB2G)
 *
 * A "case" is the unit of scoring: one piece of code with a known verdict.
 */

const fs = require("fs");
const path = require("path");

/* ------------------------------------------------------------------ *
 * CWE acceptance sets
 *
 * A detection counts if the reported CWE is in the case's accept set.
 * These are deliberately explicit rather than exact-match because our
 * analyzer legitimately reports a sibling id in two places:
 *   - memcpy size arithmetic is reported as CWE-190, not CWE-787
 *   - weak-hash / broken-crypto are one family in our rules
 * Widening is recorded in the output so the paper can state it.
 * ------------------------------------------------------------------ */

const OWASP_CATEGORIES = {
  pathtraver: { cwe: "CWE-22", accept: ["CWE-22"] },
  cmdi: { cwe: "CWE-78", accept: ["CWE-78"] },
  sqli: { cwe: "CWE-89", accept: ["CWE-89"] },
  crypto: { cwe: "CWE-327", accept: ["CWE-327", "CWE-328"] },
  hash: { cwe: "CWE-328", accept: ["CWE-328", "CWE-327"] },
};

const JULIET_GROUPS = {
  "CWE-416": {
    dirs: ["CWE416_Use_After_Free"],
    accept: ["CWE-416"],
  },
  "CWE-190": {
    dirs: ["CWE190_Integer_Overflow"],
    accept: ["CWE-190"],
  },
  "CWE-787": {
    dirs: [
      "CWE121_Stack_Based_Buffer_Overflow",
      "CWE122_Heap_Based_Buffer_Overflow",
      "CWE124_Buffer_Underwrite",
    ],
    accept: ["CWE-787", "CWE-190"],
  },
};

/** Juliet flow variants 01-21 keep the whole flow inside one function. */
const INTRA_PROCEDURAL = /_(0[1-9]|1[0-9]|2[01])\.c$/;

/* ------------------------------------------------------------------ *
 * Contamination exclusion
 * ------------------------------------------------------------------ */

/**
 * Test-case families used to fine-tune the model, read from dataset/raw.
 *
 * Juliet training files were stored with the flow-variant suffix stripped
 * ("CWE190_Integer_Overflow__char_fscanf_add.c"), so one training file
 * contaminates every variant of that family. Exclusion is therefore at
 * family level, not file level.
 */
function loadTrainingExclusions(datasetRoot) {
  const owasp = new Set();
  const julietFamilies = new Set();

  if (!fs.existsSync(datasetRoot)) {
    throw new Error(`Training dataset not found at ${datasetRoot}`);
  }

  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      const base = entry.name.replace(/\.(java|c|py)$/, "");
      if (/^BenchmarkTest\d+$/.test(base)) {
        owasp.add(base);
      } else if (base.includes("__")) {
        julietFamilies.add(julietFamily(base));
      }
    }
  };
  walk(datasetRoot);

  return { owasp, julietFamilies };
}

/** "CWE190_Integer_Overflow__char_fscanf_add_01" -> family key without variant. */
function julietFamily(base) {
  return base.replace(/_\d{2}[a-z]?$/, "");
}

/* ------------------------------------------------------------------ *
 * Sanitisation
 * ------------------------------------------------------------------ */

/**
 * Strip C/Java comments while respecting string and character literals.
 *
 * Juliet annotates every test case with "POTENTIAL FLAW:" and "FIX:"
 * comments that state the answer outright. Leaving them in would measure
 * the model's reading comprehension, not its detection ability. The static
 * analyzer is unaffected either way, so both configurations are given the
 * same sanitised input and stay directly comparable.
 */
function stripComments(code) {
  let out = "";
  let i = 0;
  const n = code.length;

  while (i < n) {
    const ch = code[i];
    const next = code[i + 1];

    if (ch === '"' || ch === "'") {
      const quote = ch;
      out += ch;
      i++;
      while (i < n) {
        if (code[i] === "\\") {
          out += code[i] + (code[i + 1] ?? "");
          i += 2;
          continue;
        }
        out += code[i];
        if (code[i] === quote) {
          i++;
          break;
        }
        i++;
      }
      continue;
    }

    if (ch === "/" && next === "/") {
      while (i < n && code[i] !== "\n") i++;
      continue;
    }

    if (ch === "/" && next === "*") {
      i += 2;
      while (i < n && !(code[i] === "*" && code[i + 1] === "/")) i++;
      i += 2;
      continue;
    }

    out += ch;
    i++;
  }

  // Collapse the blank lines the stripped comments leave behind.
  return out.replace(/\n{3,}/g, "\n\n").trim() + "\n";
}

/**
 * Remove the label that Juliet bakes into identifiers.
 * "CWE190_Integer_Overflow__char_fscanf_add_01_bad" and "goodG2B" both
 * announce the verdict; every extracted function is renamed to the same
 * neutral symbol.
 */
function neutraliseJulietNames(code, originalName) {
  return code.split(originalName).join("process_data");
}

/**
 * OWASP encodes the vulnerability category in the servlet path
 * (@WebServlet("/pathtraver-00/BenchmarkTest00001")). Replace the category
 * token so the model has to look at the code rather than the annotation.
 */
function neutraliseOwaspCategory(code, category) {
  return code.split(category).join("case");
}

/* ------------------------------------------------------------------ *
 * OWASP corpus
 * ------------------------------------------------------------------ */

function buildOwaspCases(benchRoot, exclusions, limitPerCategory) {
  const csv = path.join(benchRoot, "expectedresults-1.2.csv");
  if (!fs.existsSync(csv)) {
    throw new Error(`OWASP expected results not found at ${csv}`);
  }

  const srcDir = path.join(
    benchRoot,
    "src",
    "main",
    "java",
    "org",
    "owasp",
    "benchmark",
    "testcode"
  );

  const rows = fs
    .readFileSync(csv, "utf8")
    .split(/\r?\n/)
    .slice(1)
    .filter(Boolean)
    .map((line) => {
      const [name, category, real, cwe] = line.split(",");
      return { name, category, real: real === "true", cwe };
    })
    .filter((r) => OWASP_CATEGORIES[r.category]);

  const byCategory = new Map();
  let skippedTrained = 0;

  for (const row of rows) {
    if (exclusions.owasp.has(row.name)) {
      skippedTrained++;
      continue;
    }
    const file = path.join(srcDir, `${row.name}.java`);
    if (!fs.existsSync(file)) continue;

    if (!byCategory.has(row.category)) byCategory.set(row.category, []);
    byCategory.get(row.category).push({ ...row, file });
  }

  const cases = [];
  for (const [category, entries] of byCategory) {
    // Interleave vulnerable and safe so a truncated run stays balanced.
    const vulnerable = entries.filter((e) => e.real);
    const safe = entries.filter((e) => !e.real);
    const merged = interleave(vulnerable, safe);
    const chosen =
      limitPerCategory > 0 ? merged.slice(0, limitPerCategory) : merged;

    for (const entry of chosen) {
      const raw = fs.readFileSync(entry.file, "utf8");
      const code = neutraliseOwaspCategory(stripComments(raw), category);
      cases.push({
        id: `owasp/${entry.name}`,
        suite: "owasp",
        group: category,
        targetCwe: OWASP_CATEGORIES[category].cwe,
        accept: OWASP_CATEGORIES[category].accept,
        expected: entry.real,
        language: "java",
        fileName: `${entry.name}.java`,
        code,
      });
    }
  }

  return { cases, skippedTrained };
}

/* ------------------------------------------------------------------ *
 * Juliet corpus
 * ------------------------------------------------------------------ */

/** Extract a function body by brace matching from its signature. */
function extractFunction(code, startIndex) {
  const open = code.indexOf("{", startIndex);
  if (open === -1) return undefined;

  let depth = 0;
  for (let i = open; i < code.length; i++) {
    if (code[i] === "{") depth++;
    else if (code[i] === "}") {
      depth--;
      if (depth === 0) return code.slice(startIndex, i + 1);
    }
  }
  return undefined;
}

/**
 * Split a Juliet test case into scoring units.
 *
 * Each file contains the flaw and its fixes side by side, so the file as a
 * whole has no single verdict. The bad function is one positive case; each
 * good function is a negative case. This also matches how the static-only
 * evaluation was measured, keeping the columns comparable.
 */
function splitJulietFunctions(code, maxGood) {
  const results = [];
  const signature = /(?:static\s+)?void\s+([A-Za-z_]\w*)\s*\(\s*(?:void\s*)?\)\s*\{/g;

  let match;
  let goodCount = 0;
  while ((match = signature.exec(code)) !== null) {
    const name = match[1];
    const isBad = /_bad$/.test(name);
    const isGood = /^good/.test(name);
    if (!isBad && !isGood) continue;
    if (name === "good") continue; // dispatcher that just calls the others

    if (isGood && goodCount >= maxGood) continue;

    const body = extractFunction(code, match.index);
    if (!body) continue;

    let kind = "bad";
    if (isGood) {
      kind = name.includes("G2B")
        ? "goodG2B"
        : name.includes("B2G")
          ? "goodB2G"
          : "good";
      goodCount++;
    }

    results.push({
      kind,
      // A file can hold several functions of one kind (goodG2B1, goodG2B2);
      // the ordinal keeps case ids unique so scoring does not silently
      // collapse them into one.
      ordinal: results.filter((r) => r.kind === kind).length + 1,
      expected: isBad,
      code: neutraliseJulietNames(body, name),
    });
  }

  return results;
}

function buildJulietCases(julietRoot, exclusions, limitPerGroup, maxGood) {
  const testcases = path.join(julietRoot, "testcases");
  if (!fs.existsSync(testcases)) {
    throw new Error(`Juliet testcases not found at ${testcases}`);
  }

  const cases = [];
  let skippedTrained = 0;

  for (const [cwe, spec] of Object.entries(JULIET_GROUPS)) {
    const files = [];

    for (const dir of spec.dirs) {
      const root = path.join(testcases, dir);
      if (!fs.existsSync(root)) continue;
      collectFiles(root, files);
    }

    const eligible = [];
    for (const file of files) {
      const base = path.basename(file);
      if (!INTRA_PROCEDURAL.test(base)) continue;
      if (exclusions.julietFamilies.has(julietFamily(base.replace(/\.c$/, "")))) {
        skippedTrained++;
        continue;
      }
      eligible.push(file);
    }

    // Spread the sample across families rather than taking the first N
    // variants of the first few families.
    const spread = spreadByFamily(eligible);
    const chosen = limitPerGroup > 0 ? spread.slice(0, limitPerGroup) : spread;

    for (const file of chosen) {
      const base = path.basename(file, ".c");
      const raw = stripComments(fs.readFileSync(file, "utf8"));
      for (const fn of splitJulietFunctions(raw, maxGood)) {
        cases.push({
          id: `juliet/${cwe}/${base}#${fn.kind}${fn.ordinal}`,
          suite: "juliet",
          group: cwe,
          targetCwe: cwe,
          accept: spec.accept,
          expected: fn.expected,
          language: "c",
          fileName: `${base}.c`,
          code: fn.code,
        });
      }
    }
  }

  return { cases, skippedTrained };
}

function collectFiles(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) collectFiles(full, out);
    else if (entry.name.endsWith(".c")) out.push(full);
  }
}

/** Round-robin across test-case families so a sample covers many sinks. */
function spreadByFamily(files) {
  const families = new Map();
  for (const file of files) {
    const key = julietFamily(path.basename(file, ".c"));
    if (!families.has(key)) families.set(key, []);
    families.get(key).push(file);
  }

  const buckets = [...families.values()];
  const out = [];
  let index = 0;
  while (out.length < files.length) {
    let moved = false;
    for (const bucket of buckets) {
      if (index < bucket.length) {
        out.push(bucket[index]);
        moved = true;
      }
    }
    if (!moved) break;
    index++;
  }
  return out;
}

function interleave(a, b) {
  const out = [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (i < a.length) out.push(a[i]);
    if (i < b.length) out.push(b[i]);
  }
  return out;
}

module.exports = {
  OWASP_CATEGORIES,
  JULIET_GROUPS,
  loadTrainingExclusions,
  buildOwaspCases,
  buildJulietCases,
  stripComments,
};
