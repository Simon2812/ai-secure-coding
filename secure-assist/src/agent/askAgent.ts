import * as vscode from "vscode";
import { AgentPanel } from "./agentPanel";
import { FindingContext } from "./agentClient";
import { getCweInfo } from "../model/cweCatalog";

/** Lines of context sent around the finding — enough to reason about, small enough to stay cheap. */
const CONTEXT_LINES = 20;

/** Command id used by the "Explain with AI" code action. */
export const ASK_AGENT_COMMAND = "secure-assist.askAgent";

/**
 * Build the conversation context for a finding: the CWE, its catalog entry, and
 * the surrounding code. A window rather than the whole file keeps the request
 * small and keeps the model focused on the relevant lines.
 */
export async function askAboutFinding(
  uri: vscode.Uri,
  cwe: string,
  line: number | undefined,
  output: vscode.OutputChannel,
  suggestedFix?: { origin: string; replacement: string }
): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(uri);
  const info = getCweInfo(cwe);

  const centre = Math.max(0, (line ?? 1) - 1);
  const start = Math.max(0, centre - CONTEXT_LINES);
  const end = Math.min(doc.lineCount - 1, centre + CONTEXT_LINES);
  const snippet = doc.getText(
    new vscode.Range(start, 0, end, doc.lineAt(end).text.length)
  );

  const ctx: FindingContext = {
    cwe,
    title: info?.title,
    summary: info?.summary,
    recommendation: info?.recommendation,
    file: vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/"),
    line,
    snippet,
    suggestedFix,
  };

  await AgentPanel.explain(ctx, output);
}

/**
 * Offers "Explain with AI" on any Secure Assist diagnostic — static or model —
 * alongside the existing quick fix.
 */
export class AskAgentProvider implements vscode.CodeActionProvider {
  public static readonly kinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const ours = context.diagnostics.filter((d) =>
      typeof d.source === "string" && d.source.startsWith("Secure Assist")
    );
    if (ours.length === 0) return [];

    const seen = new Set<string>();
    const actions: vscode.CodeAction[] = [];

    for (const diag of ours) {
      const cwe = extractCwe(diag);
      if (!cwe || seen.has(cwe)) continue;
      seen.add(cwe);

      const action = new vscode.CodeAction(
        `Secure Assist: explain ${cwe} with AI`,
        vscode.CodeActionKind.QuickFix
      );
      action.command = {
        command: ASK_AGENT_COMMAND,
        title: "Explain with AI",
        arguments: [document.uri, cwe, diag.range.start.line + 1],
      };
      actions.push(action);
    }
    return actions;
  }
}

/** Pull the CWE id out of a diagnostic's code or message. */
function extractCwe(diagnostic: vscode.Diagnostic): string | undefined {
  if (typeof diagnostic.code === "string" && diagnostic.code.startsWith("CWE-")) {
    return diagnostic.code;
  }
  return diagnostic.message.match(/CWE-\d+/)?.[0];
}
