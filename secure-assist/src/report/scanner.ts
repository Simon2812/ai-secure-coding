import * as vscode from "vscode";
import { analyzeCode } from "../analyzer/analyze";
import { Finding } from "../analyzer/types";
import { projectScore, scoreForFindings, severityOf } from "./score";

/** Files the AST analyzer understands. */
const SCAN_GLOB = "**/*.{py,java,c,h,cpp,cc}";
const EXCLUDE_GLOB = "**/{node_modules,out,dist,build,.git,venv,__pycache__}/**";
const MAX_FILE_CHARS = 1_000_000;

export interface FileReport {
  /** Workspace-relative path, forward slashes. */
  path: string;
  uri: vscode.Uri;
  findings: Finding[];
  score: number;
  /** Source text, so the report can show the file's code on demand. */
  code?: string;
  /** Basename, set when the file is placed in the report's folder tree. */
  displayName?: string;
}

export interface ScanReport {
  files: FileReport[];
  score: number;
  scannedCount: number;
  cleanCount: number;
  totalFindings: number;
  counts: { critical: number; medium: number; low: number };
  /** How many findings of each CWE, most frequent first. */
  byCwe: { cwe: string; count: number }[];
  scannedAt: Date;
}

/**
 * Read a file as the user currently sees it.
 *
 * Applied fixes live in the open document until it is saved, so reading from
 * disk would re-scan the pre-fix text and undo the improvement in the report.
 * Open documents therefore take precedence over the file on disk.
 */
async function readCurrentContent(uri: vscode.Uri): Promise<string> {
  const open = vscode.workspace.textDocuments.find(
    (doc) => doc.uri.toString() === uri.toString()
  );
  if (open) return open.getText();
  return Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf-8");
}

/**
 * Run the static analyzer over every supported file in the workspace.
 *
 * Only the static analyzer runs here — it is fast and deterministic, so a
 * whole project can be scanned in seconds. The model is invoked per finding,
 * on demand, from the report.
 */
export async function scanWorkspace(
  progress?: vscode.Progress<{ message?: string; increment?: number }>,
  token?: vscode.CancellationToken
): Promise<ScanReport> {
  const uris = await vscode.workspace.findFiles(SCAN_GLOB, EXCLUDE_GLOB);
  const files: FileReport[] = [];
  const counts = { critical: 0, medium: 0, low: 0 };
  const cweTally = new Map<string, number>();
  let totalFindings = 0;

  for (let i = 0; i < uris.length; i++) {
    if (token?.isCancellationRequested) break;
    const uri = uris[i];
    const relPath = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/");

    progress?.report({
      message: `${i + 1}/${uris.length}  ${relPath}`,
      increment: 100 / Math.max(1, uris.length),
    });

    let code: string;
    try {
      code = await readCurrentContent(uri);
    } catch {
      continue; // unreadable file — skip rather than fail the whole scan
    }
    if (code.length > MAX_FILE_CHARS) continue;

    let findings: Finding[] = [];
    try {
      findings = analyzeCode(code, relPath);
    } catch {
      findings = []; // a parse failure shouldn't abort the project scan
    }

    for (const f of findings) {
      counts[severityOf(f.cweId)]++;
      cweTally.set(f.cweId, (cweTally.get(f.cweId) ?? 0) + 1);
    }
    totalFindings += findings.length;

    files.push({
      path: relPath,
      uri,
      findings,
      score: scoreForFindings(findings),
      code,
    });
  }

  // Worst files first so the report leads with what needs attention.
  files.sort((a, b) => a.score - b.score || a.path.localeCompare(b.path));

  return {
    files,
    score: projectScore(files.map((f) => f.score)),
    scannedCount: files.length,
    cleanCount: files.filter((f) => f.findings.length === 0).length,
    totalFindings,
    counts,
    byCwe: [...cweTally.entries()]
      .map(([cwe, count]) => ({ cwe, count }))
      .sort((a, b) => b.count - a.count || a.cwe.localeCompare(b.cwe)),
    scannedAt: new Date(),
  };
}
