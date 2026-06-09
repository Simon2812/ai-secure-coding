import * as vscode from "vscode";
import { analyzeCode, initAstAnalyzer } from "./analyzer/analyze";
import { Finding } from "./analyzer/types";
import { createDiagnosticCollection, updateDiagnostics } from "./diagnostics";

let isTracking = false;
const fileStore = new Map<string, string>();

export async function activate(context: vscode.ExtensionContext) {
  await initAstAnalyzer();

  const output = vscode.window.createOutputChannel("Secure Assist");
  const diagnostics = createDiagnosticCollection();
  const startCmd = vscode.commands.registerCommand("secure-assist.startTracking", () => {
    isTracking = true;
    output.show(true);
    output.appendLine("Tracking ON. Save any file to analyze it.");
    vscode.window.showInformationMessage("Secure Assist: tracking ON.");
  });

  const showStoredCmd = vscode.commands.registerCommand("secure-assist.showStoredFile", async () => {
    if (fileStore.size === 0) {
      vscode.window.showWarningMessage("Secure Assist: no stored files yet.");
      return;
    }

    const picked = await vscode.window.showQuickPick([...fileStore.keys()].sort(), {
      placeHolder: "Select a stored file to view",
    });

    if (!picked) return;

    const content = fileStore.get(picked) ?? "";
    const doc = await vscode.workspace.openTextDocument({
      content,
      language: guessLanguageFromPath(picked),
    });

    await vscode.window.showTextDocument(doc, { preview: true });
  });

  const saveSub = vscode.workspace.onDidSaveTextDocument((doc) => {
    if (!isTracking) return;
    if (doc.isUntitled) return;
    if (doc.uri.scheme !== "file") return;

    const relPath = vscode.workspace.asRelativePath(doc.uri, false).replace(/\\/g, "/");
    const content = doc.getText();

    const maxChars = 1_000_000;
    if (content.length > maxChars) {
      output.appendLine(`[SKIP] ${relPath} (too large: ${content.length} chars)`);
      return;
    }

    fileStore.set(relPath, content);

    output.appendLine(``);
    output.appendLine(`=== Analyzing ${relPath} ===`);

    const findings = analyzeCode(content, relPath);
    updateDiagnostics(diagnostics, doc, findings);

    if (findings.length === 0) {
      output.appendLine(`No findings.`);
      return;
    }

    printFindings(output, findings);
  });

  context.subscriptions.push(startCmd, showStoredCmd, saveSub, output, diagnostics);
}

export function deactivate() {}

function printFindings(output: vscode.OutputChannel, findings: Finding[]) {
  for (const finding of findings) {
    output.appendLine(
      `[${finding.severity.toUpperCase()}] ${finding.cweId} | ${finding.ruleId}`
    );
    output.appendLine(`File: ${finding.file}:${finding.line}:${finding.column}`);
    output.appendLine(`Issue: ${finding.vulnerability}`);
    output.appendLine(`Message: ${finding.message}`);
    output.appendLine(`Evidence: ${finding.evidence}`);
    output.appendLine(`---`);
  }
}

function guessLanguageFromPath(path: string): string {
  const lower = path.toLowerCase();
  if (lower.endsWith(".ts")) return "typescript";
  if (lower.endsWith(".tsx")) return "typescriptreact";
  if (lower.endsWith(".js")) return "javascript";
  if (lower.endsWith(".jsx")) return "javascriptreact";
  if (lower.endsWith(".json")) return "json";
  if (lower.endsWith(".py")) return "python";
  if (lower.endsWith(".c")) return "c";
  if (lower.endsWith(".cpp")) return "cpp";
  if (lower.endsWith(".h")) return "c";
  if (lower.endsWith(".java")) return "java";
  if (lower.endsWith(".cs")) return "csharp";
  if (lower.endsWith(".html")) return "html";
  if (lower.endsWith(".css")) return "css";
  if (lower.endsWith(".md")) return "markdown";
  return "plaintext";
}