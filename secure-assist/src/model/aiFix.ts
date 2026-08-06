import * as vscode from "vscode";
import { ModelVulnerability, ModelFix } from "./client";
import { getCweInfo, explainCwe } from "./cweCatalog";
import { findOriginRange, containsOrigin } from "./originMatch";
import { recordAppliedFix } from "./appliedFixes";

// Model results per document URI — populated by the scan command, read by the
// code-action provider to offer "Apply AI fix" quick fixes.
const modelResults = new Map<string, ModelVulnerability[]>();

const STORAGE_KEY = "secureAssist.modelResults";
let context: vscode.ExtensionContext | undefined;

/**
 * Persisted shape.
 *
 * Keyed by workspace-relative path rather than absolute URI so the results
 * survive the folder being opened from a different path — a checkout on
 * another machine, or a drive letter that changed.
 */
interface StoredResults {
  [relativePath: string]: ModelVulnerability[];
}

/**
 * Restore model findings saved by a previous session.
 *
 * An AI scan can cover a whole workspace and costs real time, so losing it on
 * window close is not acceptable. Findings are re-grounded against the file as
 * it is now: anything whose `origin` no longer appears has been edited away, so
 * it is dropped rather than shown against code that no longer exists.
 */
export async function initModelResults(ctx: vscode.ExtensionContext): Promise<void> {
  context = ctx;
  modelResults.clear();

  const stored = ctx.workspaceState.get<StoredResults>(STORAGE_KEY) ?? {};
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return;

  let restored = 0;
  let stale = 0;

  for (const [relative, vulns] of Object.entries(stored)) {
    const uri = vscode.Uri.joinPath(folders[0].uri, relative);

    let code: string;
    try {
      code = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
    } catch {
      stale += vulns.length; // file gone since the scan
      continue;
    }

    const live = vulns.filter((v) =>
      (v.fixes ?? []).some((f) => containsOrigin(code, f.origin))
    );

    stale += vulns.length - live.length;
    if (live.length === 0) continue;

    modelResults.set(uri.toString(), sortByLine(live));
    restored += live.length;
  }

  if (restored || stale) {
    console.log(
      `[secure-assist] restored ${restored} AI finding(s)` +
        (stale ? `, dropped ${stale} whose code has changed` : "")
    );
  }

  // Write back so entries dropped as stale are not re-checked next time.
  await persist();
}

/** Save the current results, converting URIs back to relative paths. */
async function persist(): Promise<void> {
  if (!context) return;

  const out: StoredResults = {};
  for (const [key, vulns] of modelResults) {
    if (vulns.length === 0) continue;
    const relative = vscode.workspace
      .asRelativePath(vscode.Uri.parse(key), false)
      .replace(/\\/g, "/");
    out[relative] = vulns;
  }

  await context.workspaceState.update(STORAGE_KEY, out);
}

export function setModelResults(uri: vscode.Uri, vulns: ModelVulnerability[]): void {
  // Kept in line order. Findings arrive in whatever order the model listed
  // them, and a reverted fix is appended when its finding is restored — both
  // of which would otherwise show out of sequence against the file.
  modelResults.set(uri.toString(), sortByLine(vulns));
  void persist();
}

/** Order findings by where they appear in the file; unplaced ones last. */
function sortByLine(vulns: ModelVulnerability[]): ModelVulnerability[] {
  return [...vulns].sort((a, b) => {
    const left = a.start_line ?? Number.MAX_SAFE_INTEGER;
    const right = b.start_line ?? Number.MAX_SAFE_INTEGER;
    return left - right;
  });
}

export function clearModelResults(uri: vscode.Uri): void {
  modelResults.delete(uri.toString());
  void persist();
}

export function getModelResults(uri: vscode.Uri): ModelVulnerability[] {
  return modelResults.get(uri.toString()) ?? [];
}

/** Files that currently carry restored or freshly scanned AI findings. */
export function filesWithModelResults(): vscode.Uri[] {
  return [...modelResults.keys()].map((key) => vscode.Uri.parse(key));
}

/** Forget every AI finding in this workspace. */
export async function clearAllModelResults(): Promise<void> {
  modelResults.clear();
  await persist();
}

/**
 * Drop a fix (and its vulnerability, once it has no fixes left) from the stored
 * results, so its squiggle goes away after the user applies it.
 */
function removeAppliedFix(uri: vscode.Uri, applied: ModelFix): void {
  const vulns = modelResults.get(uri.toString());
  if (!vulns) return;

  const remaining: ModelVulnerability[] = [];
  for (const vuln of vulns) {
    const fixes = vuln.fixes.filter(
      (f) => !(f.origin === applied.origin && f.replacement === applied.replacement)
    );
    if (fixes.length > 0) remaining.push({ ...vuln, fixes });
  }
  modelResults.set(uri.toString(), remaining);
  void persist();
}

/**
 * Convert model vulnerabilities into VSCode diagnostics (squiggles), enriched
 * with the CWE catalog and — when provided — whether the static analyzer
 * corroborated the same issue.
 */
export function modelVulnsToDiagnostics(
  document: vscode.TextDocument,
  vulns: ModelVulnerability[],
  confirmedModel?: Set<number>
): vscode.Diagnostic[] {
  const diags: vscode.Diagnostic[] = [];
  vulns.forEach((vuln, index) => {
    let range: vscode.Range;
    if (vuln.start_line != null && vuln.end_line != null) {
      const startLine = Math.max(0, vuln.start_line - 1);
      const endLine = Math.min(Math.max(startLine, vuln.end_line - 1), document.lineCount - 1);
      const endCol = document.lineAt(endLine).text.length;
      range = new vscode.Range(startLine, 0, endLine, endCol);
    } else {
      range = new vscode.Range(0, 0, 0, 0);
    }

    const info = getCweInfo(vuln.cwe);
    const confirmed = confirmedModel?.has(index) ?? false;
    const origin = confirmed ? "AI + static analyzer" : "AI";
    const header = info ? `${vuln.cwe} — ${info.title}` : vuln.cwe;
    const summary = info?.summary ?? "Model-detected vulnerability.";

    const diag = new vscode.Diagnostic(
      range,
      `[${origin}] ${header}: ${summary}`,
      vscode.DiagnosticSeverity.Warning
    );
    diag.source = "Secure Assist (AI)";
    diag.code = vuln.cwe;
    diags.push(diag);
  });
  return diags;
}

/** Command id used by the quick fix to preview-then-apply a model fix. */
export const APPLY_AI_FIX_COMMAND = "secure-assist.applyAiFix";

/** Leading whitespace of a line. */
function indentOf(line: string): string {
  return line.slice(0, line.length - line.trimStart().length);
}

/**
 * Re-indent a multi-line replacement to sit at `indent`.
 *
 * The model may return its snippet already indented. Adding the target indent
 * on top of that would double it, so the snippet's own common indentation is
 * removed first and the target applied afterwards. The first line is left alone
 * because it is inserted at an existing position that already has its indent.
 */
function reindent(replacement: string, indent: string): string {
  const lines = replacement.split("\n");
  if (lines.length === 1) return replacement;

  const rest = lines.slice(1);
  const indented = rest.filter((l) => l.trim().length > 0);
  const common = indented.length
    ? indented.reduce(
        (shortest, line) => {
          const current = indentOf(line);
          return current.length < shortest.length ? current : shortest;
        },
        indentOf(indented[0])
      )
    : "";

  const normalized = rest.map((line) => {
    if (line.trim().length === 0) return ""; // don't leave trailing whitespace
    const stripped = line.startsWith(common) ? line.slice(common.length) : line.trimStart();
    return indent + stripped;
  });

  return [lines[0], ...normalized].join("\n");
}

/**
 * Locate `origin` in the document and build the replacement text, aligned to
 * the indentation of the line the fix starts on.
 */
function resolveFix(
  document: vscode.TextDocument,
  fix: ModelFix
): { range: vscode.Range; replacement: string } | undefined {
  // Whitespace-tolerant: the model usually returns the snippet without the
  // original indentation, so an exact search would miss.
  const found = findOriginRange(document.getText(), fix.origin);
  if (!found) return undefined;

  const startPos = document.positionAt(found.start);
  const endPos = document.positionAt(found.end);
  const indent = indentOf(document.lineAt(startPos.line).text);

  return {
    range: new vscode.Range(startPos, endPos),
    replacement: reindent(fix.replacement, indent),
  };
}

/**
 * Show the model's proposed change and apply it only if the user confirms.
 *
 * The model's fixes are not always correct, so the change is never applied
 * silently — the user sees the exact before/after first.
 *
 * Returns true when the edit was written, so callers can refresh their own UI.
 */
export async function previewAndApplyFix(
  uri: vscode.Uri,
  fix: ModelFix,
  cwe: string,
  aiDiagnostics?: vscode.DiagnosticCollection
): Promise<boolean> {
  const document = await vscode.workspace.openTextDocument(uri);
  const resolved = resolveFix(document, fix);
  if (!resolved) {
    vscode.window.showWarningMessage(
      "Secure Assist: the code changed since the AI scan — re-run the scan."
    );
    return false;
  }

  const preview =
    `${explainCwe(cwe)}\n\n` +
    `— Current —\n${fix.origin}\n\n` +
    `— Suggested —\n${fix.replacement}\n\n` +
    `AI-generated fixes are not always correct. Review before applying.`;

  const choice = await vscode.window.showInformationMessage(
    preview,
    { modal: true },
    "Apply fix"
  );
  if (choice !== "Apply fix") return false;
  return applyFixEdit(uri, fix, aiDiagnostics, cwe);
}

/**
 * Write a fix without asking first.
 *
 * For callers that have already shown the change — the fixes panel renders a
 * diff, so a second confirmation dialog would just be in the way.
 */
export async function applyFixEdit(
  uri: vscode.Uri,
  fix: ModelFix,
  aiDiagnostics?: vscode.DiagnosticCollection,
  cwe = "unknown"
): Promise<boolean> {
  const document = await vscode.workspace.openTextDocument(uri);
  const resolved = resolveFix(document, fix);
  if (!resolved) {
    vscode.window.showWarningMessage(
      "Secure Assist: the code changed since the AI scan — re-run the scan."
    );
    return false;
  }

  // Capture both sides before the edit: the replacement was re-indented to
  // match this file, so it cannot be reconstructed from the model's raw fix
  // afterwards, and reverting needs the exact text on disk.
  const originalText = document.getText(resolved.range);
  const startLine = resolved.range.start.line + 1;

  const edit = new vscode.WorkspaceEdit();
  edit.replace(uri, resolved.range, resolved.replacement);
  const applied = await vscode.workspace.applyEdit(edit);
  if (!applied) {
    vscode.window.showErrorMessage("Secure Assist: could not apply the fix.");
    return false;
  }

  await recordAppliedFix({
    file: vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/"),
    cwe,
    originalText,
    insertedText: resolved.replacement,
    fix,
    line: startLine,
    at: Date.now(),
  });

  // The finding no longer applies to the edited code — drop it and refresh the
  // squiggles so a stale AI marker doesn't linger on the fixed line.
  removeAppliedFix(uri, fix);
  if (aiDiagnostics) {
    const updated = await vscode.workspace.openTextDocument(uri);
    aiDiagnostics.set(uri, modelVulnsToDiagnostics(updated, getModelResults(uri)));
  }
  return true;
}

/**
 * Drop AI findings whose `origin` text is no longer present in the document and
 * refresh the squiggles. Called after edits so fixed/removed code doesn't keep
 * showing a marker from an earlier scan.
 */
export function pruneStaleAiFindings(
  document: vscode.TextDocument,
  aiDiagnostics: vscode.DiagnosticCollection
): void {
  const uriKey = document.uri.toString();
  const vulns = modelResults.get(uriKey);
  if (!vulns || vulns.length === 0) return;

  const text = document.getText();
  const remaining: ModelVulnerability[] = [];
  for (const vuln of vulns) {
    const fixes = vuln.fixes.filter((f) => containsOrigin(text, f.origin));
    if (fixes.length > 0) remaining.push({ ...vuln, fixes });
  }

  if (remaining.length === vulns.length) return; // nothing went stale
  modelResults.set(uriKey, remaining);
  aiDiagnostics.set(document.uri, modelVulnsToDiagnostics(document, remaining));
}

/** True if the vulnerability's line range covers the cursor/selection. */
function vulnCoversRange(vuln: ModelVulnerability, range: vscode.Range): boolean {
  if (vuln.start_line == null || vuln.end_line == null) return true;
  return range.start.line >= vuln.start_line - 1 && range.start.line <= vuln.end_line - 1;
}

/** Offers "Apply AI fix" quick fixes for model findings on the current line. */
export class AiFixProvider implements vscode.CodeActionProvider {
  public static readonly kinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range
  ): vscode.CodeAction[] {
    const vulns = modelResults.get(document.uri.toString());
    if (!vulns || vulns.length === 0) return [];

    const actions: vscode.CodeAction[] = [];
    for (const vuln of vulns) {
      if (!vulnCoversRange(vuln, range)) continue;
      for (const fix of vuln.fixes) {
        // Only offer the fix if its origin still matches the current text.
        if (!resolveFix(document, fix)) continue;
        const action = new vscode.CodeAction(
          `Secure Assist: preview AI fix for ${vuln.cwe}`,
          vscode.CodeActionKind.QuickFix
        );
        // Runs a command instead of carrying an edit, so the user sees the
        // proposed change before anything is written to their file.
        action.command = {
          command: APPLY_AI_FIX_COMMAND,
          title: "Preview AI fix",
          arguments: [document.uri, fix, vuln.cwe],
        };
        action.isPreferred = true;
        actions.push(action);
      }
    }
    return actions;
  }
}
