import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

/** Display metadata for one CWE, as stored in resources/cwe_catalog.json. */
export interface CweInfo {
  title: string;
  severity: string;
  summary: string;
  impact: string[];
  recommendation: string;
}

let catalog: Record<string, CweInfo> = {};

/**
 * Load the shared CWE catalog (the same file the CLI uses) from the extension
 * bundle. Failing to load is non-fatal — findings just render without the
 * enrichment.
 */
export function loadCweCatalog(context: vscode.ExtensionContext): void {
  const file = path.join(context.extensionPath, "resources", "cwe_catalog.json");
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (parsed && typeof parsed === "object") catalog = parsed;
  } catch {
    catalog = {};
  }
}

/** Metadata for a CWE, or undefined when it isn't in the catalog. */
export function getCweInfo(cwe: string | undefined): CweInfo | undefined {
  if (!cwe) return undefined;
  return catalog[cwe];
}

/** Short "CWE-89 — SQL Injection" style label for diagnostics. */
export function describeCwe(cwe: string): string {
  const info = getCweInfo(cwe);
  return info ? `${cwe} — ${info.title}` : cwe;
}

/** Multi-line explanation used for hovers and Output logging. */
export function explainCwe(cwe: string): string {
  const info = getCweInfo(cwe);
  if (!info) return cwe;
  const lines = [
    `${cwe} — ${info.title} (${info.severity})`,
    info.summary,
  ];
  if (info.impact?.length) lines.push(`Impact: ${info.impact.join("; ")}`);
  if (info.recommendation) lines.push(`Recommendation: ${info.recommendation}`);
  return lines.join("\n");
}
