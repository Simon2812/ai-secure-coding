import * as fs from "fs";
import * as path from "path";
import { Finding } from "../analyzer/types";
import { analyzeCode } from "../analyzer/analyze";
import { initAstAnalyzer, astAnalyzeCode } from "../analyzer/ast/astAnalyzer";

const REPO_ROOT = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(__dirname, "..", "..", "..");
const METADATA_DIR = path.join(REPO_ROOT, "dataset", "metadata");
// Optional: comma-separated CWE filter, e.g. "CWE-327,CWE-328"
const CWE_FILTER: Set<string> | null = process.argv[3]
  ? new Set(process.argv[3].split(",").map(s => s.trim()))
  : null;
const SECURE_ASSIST_ROOT = path.resolve(__dirname, "..", "..");
const ENRICHED_DIR = path.join(SECURE_ASSIST_ROOT, "enriched");

interface Vulnerability {
  id: string;
  cwe: string;
  fixes: Array<{ origin: string; replacement: string }>;
}

interface Metadata {
  schema_version: string;
  id: string;
  language: string;
  path: string;
  split: string;
  source: { type: string; name: string | null };
  vulnerabilities: Vulnerability[];
}

interface EnrichedMetadata extends Metadata {
  static_findings: Finding[];
  enriched_at: string;
}

// CWEs where AST outperforms regex
const AST_STRONG = new Set(["CWE-22", "CWE-78", "CWE-89", "CWE-190", "CWE-259", "CWE-321", "CWE-327", "CWE-328", "CWE-416", "CWE-787", "MULTI-CWE"]);

function pickAnalyzer(metaPath: string, code: string, codePath: string): Finding[] {
  const cweFolder = path.relative(METADATA_DIR, metaPath).split(path.sep)[0];
  if (AST_STRONG.has(cweFolder)) {
    return astAnalyzeCode(code, codePath);
  }
  return analyzeCode(code, codePath);
}

function walkJson(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkJson(fullPath));
    } else if (entry.isFile() && entry.name.endsWith(".json")) {
      results.push(fullPath);
    }
  }
  return results;
}

async function main() {
  await initAstAnalyzer();
  const allFiles = walkJson(METADATA_DIR);
  const metadataFiles = CWE_FILTER
    ? allFiles.filter(f => {
        const cweFolder = path.relative(METADATA_DIR, f).split(path.sep)[0];
        return CWE_FILTER.has(cweFolder);
      })
    : allFiles;
  if (CWE_FILTER) console.log(`CWE filter: ${[...CWE_FILTER].join(", ")}`);

  let processed = 0;
  let skipped = 0;
  let errors = 0;

  console.log(`Found ${metadataFiles.length} metadata files.\n`);

  for (const metaPath of metadataFiles) {
    let meta: Metadata;

    try {
      meta = JSON.parse(fs.readFileSync(metaPath, "utf-8")) as Metadata;
    } catch (e) {
      console.error(`[ERROR] Failed to parse ${metaPath}: ${e}`);
      errors++;
      continue;
    }

    const codePath = path.join(REPO_ROOT, meta.path.replace(/^\//, ""));

    if (!fs.existsSync(codePath)) {
      console.warn(`[SKIP] Code file not found: ${codePath}`);
      skipped++;
      continue;
    }

    const code = fs.readFileSync(codePath, "utf-8");
    const findings = pickAnalyzer(metaPath, code, codePath);

    const enriched: EnrichedMetadata = {
      ...meta,
      static_findings: findings,
      enriched_at: new Date().toISOString(),
    };

    const relPath = path.relative(METADATA_DIR, metaPath);
    const outPath = path.join(ENRICHED_DIR, relPath);

    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(enriched, null, 2), "utf-8");

    console.log(`[OK] ${meta.id} → ${findings.length} finding(s)`);
    processed++;
  }

  console.log(`\nDone. Processed: ${processed}, Skipped: ${skipped}, Errors: ${errors}`);
}

main().catch(err => { console.error(err); process.exit(1); });
