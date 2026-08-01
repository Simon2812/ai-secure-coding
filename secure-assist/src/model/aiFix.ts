import * as vscode from "vscode";
import { ModelVulnerability, ModelFix } from "./client";
import { getCweInfo, explainCwe } from "./cweCatalog";

// Model results per document URI — populated by the scan command, read by the
// code-action provider to offer "Apply AI fix" quick fixes.
const modelResults = new Map<string, ModelVulnerability[]>();

export function setModelResults(uri: vscode.Uri, vulns: ModelVulnerability[]): void {
  modelResults.set(uri.toString(), vulns);
}

export function clearModelResults(uri: vscode.Uri): void {
  modelResults.delete(uri.toString());
}

export function getModelResults(uri: vscode.Uri): ModelVulnerability[] {
  return modelResults.get(uri.toString()) ?? [];
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

/**
 * Locate `origin` in the document and build the replacement text, preserving
 * the indentation of the line the fix starts on (so multi-line fixes line up).
 */
function resolveFix(
  document: vscode.TextDocument,
  fix: ModelFix
): { range: vscode.Range; replacement: string } | undefined {
  const text = document.getText();
  const idx = text.indexOf(fix.origin);
  if (idx < 0) return undefined;

  const startPos = document.positionAt(idx);
  const endPos = document.positionAt(idx + fix.origin.length);

  const lineText = document.lineAt(startPos.line).text;
  const indent = lineText.slice(0, lineText.length - lineText.trimStart().length);

  const replacement = fix.replacement
    .split("\n")
    .map((line, i) => (i === 0 ? line : indent + line))
    .join("\n");

  return { range: new vscode.Range(startPos, endPos), replacement };
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

  const edit = new vscode.WorkspaceEdit();
  edit.replace(uri, resolved.range, resolved.replacement);
  const applied = await vscode.workspace.applyEdit(edit);
  if (!applied) {
    vscode.window.showErrorMessage("Secure Assist: could not apply the fix.");
    return false;
  }

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
    const fixes = vuln.fixes.filter((f) => text.includes(f.origin));
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
