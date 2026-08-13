import * as vscode from "vscode";
import { fixAt, APPLY_AI_FIX_COMMAND } from "./model/aiFix";
import { getCweInfo } from "./model/cweCatalog";
import { ASK_AGENT_COMMAND } from "./agent/askAgent";

/**
 * Runs the action a hover link was clicked for.
 *
 * A command URI can only carry JSON, so a `vscode.Uri` arrives as a plain
 * object and the fix itself cannot be passed at all. The hover therefore sends
 * identifiers and this rebuilds the real arguments, which also means the fix
 * applied is the one that is current rather than the one that existed when the
 * hover was drawn.
 */
export const HOVER_ACTION_COMMAND = "secure-assist.internal.hoverAction";

interface HoverAction {
  action: "fix" | "explain" | "dismiss";
  uri: string;
  cwe: string;
  line: number;
  endLine: number;
}

export function registerHoverActions(): vscode.Disposable {
  return vscode.commands.registerCommand(HOVER_ACTION_COMMAND, async (raw: HoverAction) => {
    const uri = vscode.Uri.parse(raw.uri);

    switch (raw.action) {
      case "explain":
        await vscode.commands.executeCommand(ASK_AGENT_COMMAND, uri, raw.cwe, raw.line);
        return;

      case "dismiss":
        await vscode.commands.executeCommand(
          "secure-assist.reportFalsePositive",
          uri,
          raw.cwe,
          raw.line,
          raw.endLine
        );
        return;

      case "fix": {
        const document = await vscode.workspace.openTextDocument(uri);
        const found = fixAt(document, new vscode.Position(raw.line - 1, 0), raw.cwe);
        if (!found) {
          vscode.window.showInformationMessage(
            "Secure Assist: that fix no longer matches the current code."
          );
          return;
        }
        await vscode.commands.executeCommand(
          APPLY_AI_FIX_COMMAND,
          uri,
          found.fix,
          found.vuln.cwe
        );
        return;
      }
    }
  });
}

/**
 * A Secure Assist section in the hover, with the tool's own actions.
 *
 * These are also offered as quick fixes, but the quick-fix menu mixes them in
 * with every other provider's suggestions and takes a second click to open.
 * Putting them on the hover means the finding and what can be done about it are
 * in the same place.
 */
export class SecureAssistHoverProvider implements vscode.HoverProvider {
  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position
  ): vscode.Hover | undefined {
    const ours = vscode.languages
      .getDiagnostics(document.uri)
      .filter(
        (d) =>
          typeof d.source === "string" &&
          d.source.startsWith("Secure Assist") &&
          d.range.contains(position)
      );
    if (ours.length === 0) return undefined;

    const md = new vscode.MarkdownString();
    md.isTrusted = true;          // command: links are inert without this
    md.supportThemeIcons = true;

    const seen = new Set<string>();
    for (const diag of ours) {
      const cwe = cweOf(diag);
      if (!cwe || seen.has(cwe)) continue;
      seen.add(cwe);

      const line = diag.range.start.line + 1;
      const endLine = diag.range.end.line + 1;
      const title = getCweInfo(cwe)?.title;
      const link = (action: HoverAction["action"], label: string) => {
        const args = encodeURIComponent(
          JSON.stringify([{ action, uri: document.uri.toString(), cwe, line, endLine }])
        );
        return `[${label}](command:${HOVER_ACTION_COMMAND}?${args})`;
      };

      if (seen.size > 1) md.appendMarkdown("\n\n---\n\n");
      md.appendMarkdown(`**$(shield) Secure Assist** &nbsp; ${cwe}${title ? ` - ${title}` : ""}\n\n`);

      // "Apply AI fix" appears only when the model has one that still matches
      // the current text; there is nothing to apply otherwise.
      const actions: string[] = [];
      if (fixAt(document, position, cwe)) actions.push(link("fix", "$(zap) Apply AI fix"));
      actions.push(link("explain", "$(comment-discussion) Explain"));
      actions.push(link("dismiss", "$(circle-slash) Not a vulnerability"));

      md.appendMarkdown(actions.join(" &nbsp;·&nbsp; "));
    }

    // Anchored to the first finding so the popup sits against the flagged code.
    return new vscode.Hover(md, ours[0].range);
  }
}

/** Pull the CWE id out of a diagnostic's code or message. */
function cweOf(diagnostic: vscode.Diagnostic): string | undefined {
  const code = diagnostic.code;
  const raw =
    typeof code === "string" || typeof code === "number"
      ? String(code)
      : typeof code === "object" && code !== null
        ? String((code as { value: string | number }).value)
        : "";
  const match = /CWE-\d+/i.exec(raw) ?? /CWE-\d+/i.exec(diagnostic.message);
  return match?.[0].toUpperCase();
}
