import * as vscode from "vscode";
import { analyzeCode, initAstAnalyzer } from "./analyzer/analyze";
import { Finding } from "./analyzer/types";
import { createDiagnosticCollection, updateDiagnostics } from "./diagnostics";
import { analyzeWithModel, getModelEndpoint } from "./model/client";
import {
  AiFixProvider,
  setModelResults,
  modelVulnsToDiagnostics,
  previewAndApplyFix,
  pruneStaleAiFindings,
  APPLY_AI_FIX_COMMAND,
} from "./model/aiFix";
import { ModelFix } from "./model/client";
import { loadCweCatalog, explainCwe } from "./model/cweCatalog";
import { correlateFindings } from "./model/correlation";

// Analysis is on by default — the user should get findings without having to
// discover a "start tracking" command first.
let isTracking = true;
// Reveal the Secure Assist output channel once, on the first result.
let hasRevealedOutput = false;
const fileStore = new Map<string, string>();

// Debounce timers for live (on-change) analysis, keyed by document URI.
const liveTimers = new Map<string, ReturnType<typeof setTimeout>>();
const LIVE_DEBOUNCE_MS = 500;

// Extensions the AST analyzer supports — gates the live-on-change work so we
// don't re-analyze unrelated files on every keystroke.
const SUPPORTED_SOURCE = /\.(py|java|c|h|cpp|cc)$/i;

export async function activate(context: vscode.ExtensionContext) {
  await initAstAnalyzer();
  // Shared CWE metadata (same catalog the CLI uses) for enriched findings.
  loadCweCatalog(context);

  const output = vscode.window.createOutputChannel("Secure Assist");
  const diagnostics = createDiagnosticCollection();
  const aiDiagnostics = vscode.languages.createDiagnosticCollection("secure-assist-ai");
  const startCmd = vscode.commands.registerCommand("secure-assist.startTracking", () => {
    isTracking = true;
    output.show(true);
    output.appendLine("Tracking ON. Editing or saving a file will analyze it.");
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

  // Remembers the last findings logged per file so live-on-change only writes
  // to the Output channel when the findings actually change — not on every
  // keystroke with the same result.
  const lastFindingsSig = new Map<string, string>();

  // Run the static analyzer on a document and refresh its diagnostics.
  //   verbose    – always log to the Output channel (on save)
  //   logChanges – log only when the findings differ from last time (live mode)
  const runStaticAnalysis = (
    doc: vscode.TextDocument,
    opts: { verbose: boolean; logChanges?: boolean }
  ) => {
    if (!isTracking) return;
    if (doc.isUntitled) return;
    if (doc.uri.scheme !== "file") return;

    const relPath = vscode.workspace.asRelativePath(doc.uri, false).replace(/\\/g, "/");
    const content = doc.getText();

    const maxChars = 1_000_000;
    if (content.length > maxChars) {
      if (opts.verbose) output.appendLine(`[SKIP] ${relPath} (too large: ${content.length} chars)`);
      return;
    }

    fileStore.set(relPath, content);

    const findings = analyzeCode(content, relPath);
    updateDiagnostics(diagnostics, doc, findings);

    const key = doc.uri.toString();
    const signature = findings
      .map((f) => `${f.cweId}:${f.line}:${f.column}:${f.ruleId}`)
      .sort()
      .join("|");
    const changed = lastFindingsSig.get(key) !== signature;
    lastFindingsSig.set(key, signature);

    if (opts.verbose || (opts.logChanges && changed)) {
      // Reveal our channel the first time we have something to say, so the
      // results aren't hidden behind whatever channel is currently selected.
      if (!hasRevealedOutput) {
        hasRevealedOutput = true;
        output.show(true);
      }
      output.appendLine(``);
      output.appendLine(`=== Analyzing ${relPath} ===`);
      if (findings.length === 0) output.appendLine(`No findings.`);
      else printFindings(output, findings);
    }
  };

  // On save: full analysis with Output logging.
  const saveSub = vscode.workspace.onDidSaveTextDocument((doc) => {
    runStaticAnalysis(doc, { verbose: true });
  });

  // Live mode: on every edit, debounce briefly then re-run the (fast) static
  // analyzer so squiggles update as you type. Quiet — no Output spam.
  const changeSub = vscode.workspace.onDidChangeTextDocument((event) => {
    const doc = event.document;
    if (!isTracking) return;
    if (doc.uri.scheme !== "file") return;
    if (!SUPPORTED_SOURCE.test(doc.fileName)) return;

    const key = doc.uri.toString();
    const pending = liveTimers.get(key);
    if (pending) clearTimeout(pending);
    liveTimers.set(
      key,
      setTimeout(() => {
        liveTimers.delete(key);
        runStaticAnalysis(doc, { verbose: false, logChanges: true });
        // AI findings are a snapshot from the last scan. Once the text changes,
        // drop any whose origin no longer appears — they refer to code that is
        // gone, so their squiggles would be stale.
        pruneStaleAiFindings(doc, aiDiagnostics);
      }, LIVE_DEBOUNCE_MS)
    );
  });

  // "Scan with AI" — run the fine-tuned model on the active file (on demand).
  const scanAiCmd = vscode.commands.registerCommand("secure-assist.scanWithAI", async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showWarningMessage("Secure Assist: open a file to scan with AI.");
      return;
    }
    const doc = editor.document;
    const relPath = vscode.workspace.asRelativePath(doc.uri, false).replace(/\\/g, "/");
    const code = doc.getText();
    const staticFindings = analyzeCode(code, relPath);

    // Surface our channel so results are visible without hunting the dropdown.
    output.show(true);
    output.appendLine(``);
    output.appendLine(`=== Static analysis (sent to model): ${relPath} ===`);
    if (staticFindings.length === 0) output.appendLine("No static findings.");
    else printFindings(output, staticFindings);

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Secure Assist: AI analysis",
        cancellable: true,
      },
      async (progress, token) => {
        const started = Date.now();
        progress.report({ message: "running model…" });
        try {
          const result = await analyzeWithModel(code, staticFindings, getModelEndpoint(), token);
          const vulns = result.vulnerabilities ?? [];

          // Cross-check the two sources so we can mark issues that both agree on.
          const correlation = correlateFindings(staticFindings, vulns);

          setModelResults(doc.uri, vulns);
          aiDiagnostics.set(
            doc.uri,
            modelVulnsToDiagnostics(doc, vulns, correlation.confirmedModel)
          );

          const secs = ((Date.now() - started) / 1000).toFixed(1);
          output.appendLine(``);
          output.appendLine(`=== AI analysis: ${relPath} (${secs}s) ===`);
          if (vulns.length === 0) {
            output.appendLine("No AI findings.");
          } else {
            vulns.forEach((v, i) => {
              const confirmed = correlation.confirmedModel.has(i);
              const tag = confirmed ? "AI + static" : "AI only";
              output.appendLine(
                `[${tag}] ${v.cwe}  lines ${v.start_line ?? "?"}-${v.end_line ?? "?"}`
              );
              for (const l of explainCwe(v.cwe).split("\n").slice(1)) {
                output.appendLine(`  ${l}`);
              }
              for (const fix of v.fixes ?? []) {
                output.appendLine(`  Origin:`);
                for (const l of (fix.origin ?? "").split("\n")) output.appendLine(`    ${l}`);
                output.appendLine(`  Replacement:`);
                for (const l of (fix.replacement ?? "").split("\n")) output.appendLine(`    ${l}`);
              }
              output.appendLine(`---`);
            });

            // Findings the static analyzer reported that the model did not.
            const missedByModel = staticFindings.filter(
              (_f, i) => !correlation.confirmedStatic.has(i)
            );
            if (missedByModel.length > 0) {
              output.appendLine(`Static-only (not reported by the model):`);
              for (const f of missedByModel) {
                output.appendLine(`  [static only] ${f.cweId} at line ${f.line}`);
              }
              output.appendLine(`---`);
            }
          }

          const bothCount = correlation.confirmedModel.size;
          vscode.window.showInformationMessage(
            `Secure Assist: AI found ${vulns.length} issue(s) in ${secs}s ` +
              `(${bothCount} confirmed by both).`
          );
        } catch (err: any) {
          if (err?.message === "Cancelled") {
            output.appendLine("AI analysis cancelled.");
            return;
          }
          vscode.window.showErrorMessage(`Secure Assist: ${err?.message ?? err}`);
          output.appendLine(`AI analysis error: ${err?.message ?? err}`);
        }
      }
    );
  });

  // Always-visible status-bar button to trigger the AI scan.
  const scanButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  scanButton.text = "$(shield) Scan with AI";
  scanButton.tooltip = "Secure Assist: run AI vulnerability analysis on the active file";
  scanButton.command = "secure-assist.scanWithAI";
  scanButton.show();

  // Backing command for the quick fix — shows the proposed change, then applies
  // it only on confirmation (model fixes are not always correct).
  const applyAiFixCmd = vscode.commands.registerCommand(
    APPLY_AI_FIX_COMMAND,
    async (uri: vscode.Uri, fix: ModelFix, cwe: string) => {
      await previewAndApplyFix(uri, fix, cwe, aiDiagnostics);
    }
  );

  // Quick-fix provider: "Apply AI fix" on lines the model flagged.
  const aiFixProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: "file" },
    new AiFixProvider(),
    { providedCodeActionKinds: AiFixProvider.kinds }
  );

  context.subscriptions.push(
    startCmd,
    showStoredCmd,
    saveSub,
    changeSub,
    scanAiCmd,
    applyAiFixCmd,
    scanButton,
    aiFixProvider,
    output,
    diagnostics,
    aiDiagnostics
  );
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