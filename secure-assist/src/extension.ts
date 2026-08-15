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
  getModelResults,
  initModelResults,
  filesWithModelResults,
  clearAllModelResults,
  onDidChangeModelResults,
  APPLY_AI_FIX_COMMAND,
} from "./model/aiFix";
import { ModelFix } from "./model/client";
import { loadCweCatalog, explainCwe } from "./model/cweCatalog";
import { correlateFindings } from "./model/correlation";
import { ReportPanel } from "./report/reportPanel";
import {
  initSuppressions,
  filterSuppressed,
  filterSuppressedVulns,
  suppress,
  lineTextAt,
  listSuppressions,
  confirmSuppression,
} from "./report/suppressions";
import { DismissedPanel } from "./report/dismissedPanel";
import { SecureAssistHoverProvider, registerHoverActions } from "./hover";
import { groundVulnerabilities, findOriginRange } from "./model/originMatch";
import { initAppliedFixes, appliedFixesIn } from "./model/appliedFixes";
import { recordActivity } from "./report/history";
import { filterDisabledCwes, filterDisabledCweVulns, isLiveModeEnabled } from "./report/settings";
import { SettingsPanel } from "./report/settingsPanel";
import { FixPanel } from "./model/fixPanel";
import { AskAgentProvider, askAboutFinding, ASK_AGENT_COMMAND } from "./agent/askAgent";
import { AgentPanel } from "./agent/agentPanel";

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
  // Dismissed false positives, persisted per workspace.
  initSuppressions(context);
  // Applied AI fixes, so they can be reverted in a later session.
  initAppliedFixes(context);

  const output = vscode.window.createOutputChannel("Secure Assist");
  const diagnostics = createDiagnosticCollection();
  const aiDiagnostics = vscode.languages.createDiagnosticCollection("secure-assist-ai");

  // AI findings from previous sessions. A workspace-wide AI scan is slow and
  // costs GPU time, so it is restored rather than thrown away on window close.
  // Findings whose code has since changed are dropped during the restore.
  await initModelResults(context);
  for (const uri of filesWithModelResults()) {
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const rel = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/");
      aiDiagnostics.set(
        uri,
        modelVulnsToDiagnostics(
          doc,
          filterSuppressedVulns(getModelResults(uri), rel, doc.getText())
        )
      );
    } catch {
      /* file unreadable now — its findings were already dropped on restore */
    }
  }
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

    // Findings the developer dismissed as false positives never come back.
    const findings = filterDisabledCwes(filterSuppressed(analyzeCode(content, relPath), relPath, content));
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

  // On open: analyse quietly, so a file has its squiggles as soon as it is
  // shown rather than only after the first save. Without this a reopened
  // workspace looks clean until the user edits something.
  const openSub = vscode.workspace.onDidOpenTextDocument((doc) => {
    if (!SUPPORTED_SOURCE.test(doc.fileName)) return;
    runStaticAnalysis(doc, { verbose: false });
  });

  // Documents restored by VSCode at startup are already open, so no open
  // event fires for them — they have to be analysed explicitly.
  for (const doc of vscode.workspace.textDocuments) {
    if (SUPPORTED_SOURCE.test(doc.fileName)) {
      runStaticAnalysis(doc, { verbose: false });
    }
  }

  // Live mode: on every edit, debounce briefly then re-run the (fast) static
  // analyzer so squiggles update as you type. Quiet — no Output spam.
  const changeSub = vscode.workspace.onDidChangeTextDocument((event) => {
    const doc = event.document;
    if (!isTracking) return;
    if (!isLiveModeEnabled()) return; // analyse on save only
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
    const staticFindings = filterDisabledCwes(
      filterSuppressed(analyzeCode(code, relPath), relPath, code)
    );

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

          // Discard findings the model could not tie to real code — usually a
          // remembered fix pattern rather than something it read in this file.
          const { grounded, discarded } = groundVulnerabilities(
            result.vulnerabilities ?? [],
            code
          );
          for (const d of discarded) {
            output.appendLine(
              `[AI] ignored ${d.cwe}: its origin does not appear in this file ` +
                `(${(d.fixes?.[0]?.origin ?? "no fix").split("\n")[0].trim()})`
            );
          }

          const vulns = filterDisabledCweVulns(
            filterSuppressedVulns(grounded, relPath, code)
          );

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

          refreshFixesButton();
          await recordActivity(context, {
            kind: "scan",
            file: relPath,
            detail: `AI scan · ${vulns.length} finding(s) in ${secs}s`,
          });

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

  // Opens the AI fixes panel for the active file. Surfaced only once a scan has
  // produced fixes, so the button is never a no-op.
  const fixesButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 101);
  fixesButton.command = "secure-assist.showFixes";
  fixesButton.tooltip = "Secure Assist: review and apply the AI's suggested fixes";

  const showFixesCmd = vscode.commands.registerCommand("secure-assist.showFixes", () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) return;
    FixPanel.show(editor.document.uri, aiDiagnostics, output, context);
  });

  /** Show the fixes button while the active file has fixes to offer or undo. */
  const refreshFixesButton = () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      fixesButton.hide();
      return;
    }
    // Count what the panel will actually show: findings that still have at
    // least one fix whose original text can be located in the file. Counting
    // raw fix objects promised more than the panel could deliver, because a
    // fix whose origin no longer matches is filtered out when it opens.
    const code = editor.document.getText();
    const count = getModelResults(editor.document.uri).filter((v) =>
      (v.fixes ?? []).some((f) => findOriginRange(code, f.origin))
    ).length;

    // Applying the last fix used to hide the button, which stranded the applied
    // fixes: the panel is the only way to revert them, and closing it left no
    // way back in. The button stays while there is anything to undo.
    const relPath = vscode.workspace
      .asRelativePath(editor.document.uri, false)
      .replace(/\\/g, "/");
    const applied = appliedFixesIn(relPath, code).length;

    if (count === 0 && applied === 0) {
      fixesButton.hide();
      return;
    }

    if (count > 0) {
      fixesButton.text = `$(zap) ${count} AI fix${count === 1 ? "" : "es"}`;
      fixesButton.tooltip = "Secure Assist: review and apply the AI's suggested fixes";
    } else {
      fixesButton.text = `$(history) ${applied} applied`;
      fixesButton.tooltip = "Secure Assist: review or revert the fixes applied to this file";
    }
    fixesButton.show();
  };

  const editorSub = vscode.window.onDidChangeActiveTextEditor(() => {
    refreshFixesButton();
    refreshDismissedButton();
  });

  // Applying a fix removes the finding and records something revertible, and
  // reverting does the reverse. Both write to the model-results store, so one
  // subscription keeps the button in step with either.
  const fixesButtonSub = onDidChangeModelResults(() => refreshFixesButton());

  // Deep scan: static analysis over the whole workspace, rendered as a report.
  const deepScanCmd = vscode.commands.registerCommand("secure-assist.deepScan", async () => {
    await ReportPanel.show(output, context);
  });

  const deepScanButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 99);
  deepScanButton.text = "$(search) Deep Scan Project";
  deepScanButton.tooltip = "Secure Assist: scan every source file and open the security report";
  deepScanButton.command = "secure-assist.deepScan";
  deepScanButton.show();

  // Backing command for the quick fix — shows the proposed change, then applies
  // it only on confirmation (model fixes are not always correct).
  const applyAiFixCmd = vscode.commands.registerCommand(
    APPLY_AI_FIX_COMMAND,
    async (uri: vscode.Uri, fix: ModelFix, cwe: string) => {
      const applied = await previewAndApplyFix(uri, fix, cwe, aiDiagnostics);
      if (!applied) return;
      await recordActivity(context, {
        kind: "fix",
        file: vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/"),
        cwe,
        detail: "applied from the editor",
      });
    }
  );

  // Settings: which weaknesses are reported, live mode, model connection and
  // the stored suppression / history data.
  const settingsCmd = vscode.commands.registerCommand("secure-assist.settings", () => {
    SettingsPanel.show(context, () => {
      // Re-analyse the visible file so a toggled CWE takes effect immediately.
      const editor = vscode.window.activeTextEditor;
      if (editor) runStaticAnalysis(editor.document, { verbose: false });
      refreshDismissedButton();
    });
  });

  const settingsButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 97);
  settingsButton.text = "$(gear)";
  settingsButton.tooltip = "Secure Assist: settings";
  settingsButton.command = "secure-assist.settings";
  settingsButton.show();

  // Per-file view of what has been dismissed here, with restore. The project
  // report covers the whole workspace; this is for the file being edited.
  const dismissedButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 98);
  dismissedButton.command = "secure-assist.showDismissed";
  dismissedButton.tooltip = "Secure Assist: findings dismissed in this file";

  /** Re-analyse a file so a restored finding reappears immediately. */
  const reanalyse = async (uri: vscode.Uri) => {
    const doc = await vscode.workspace.openTextDocument(uri);
    const rel = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/");
    const text = doc.getText();
    updateDiagnostics(
      diagnostics,
      doc,
      filterDisabledCwes(filterSuppressed(analyzeCode(text, rel), rel, text))
    );
    refreshDismissedButton();
  };

  const showDismissedCmd = vscode.commands.registerCommand(
    "secure-assist.showDismissed",
    () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) return;
      DismissedPanel.show(editor.document.uri, reanalyse);
    }
  );

  // Not declared in package.json, so it stays out of the command palette: it
  // exists only so the report webview can refresh the status bar after a
  // dismissal, without holding a reference to it.
  const refreshStatusCmd = vscode.commands.registerCommand(
    "secure-assist.internal.refreshStatusBar",
    () => refreshDismissedButton()
  );

  // Same reasoning: the settings panel can clear the scan history, but the
  // report panel holds its own copy, so it needs telling to reload.
  const refreshHistoryCmd = vscode.commands.registerCommand(
    "secure-assist.internal.refreshReportHistory",
    () => ReportPanel.reloadHistory(context)
  );

  // Clearing AI findings has to take their squiggles with it, otherwise the
  // editor keeps showing findings the extension no longer holds.
  const refreshAiCmd = vscode.commands.registerCommand(
    "secure-assist.internal.refreshAiDiagnostics",
    async () => {
      // Rebuilt from the store rather than just emptied: clearing the whole
      // collection also took the squiggles off files that still have findings,
      // so discarding one file's results blanked every other file until it was
      // reopened. Mirrors the restore done at activation.
      aiDiagnostics.clear();
      for (const uri of filesWithModelResults()) {
        try {
          const doc = await vscode.workspace.openTextDocument(uri);
          const rel = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/");
          aiDiagnostics.set(
            uri,
            modelVulnsToDiagnostics(
              doc,
              filterSuppressedVulns(getModelResults(uri), rel, doc.getText())
            )
          );
        } catch {
          /* file unreadable now — its findings were already dropped */
        }
      }
      refreshFixesButton();
    }
  );

  function refreshDismissedButton(): void {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      dismissedButton.hide();
      return;
    }
    const rel = vscode.workspace.asRelativePath(editor.document.uri, false).replace(/\\/g, "/");
    const count = listSuppressions().filter((s) => s.file === rel).length;
    if (count === 0) {
      dismissedButton.hide();
      return;
    }
    dismissedButton.text = `$(circle-slash) ${count} dismissed`;
    dismissedButton.show();
  }

  // Dismiss a finding as a false positive. Keyed on the text of the flagged
  // line, so it stays dismissed if the code moves but returns if the code
  // itself changes.
  const dismissCmd = vscode.commands.registerCommand(
    "secure-assist.reportFalsePositive",
    async (uri: vscode.Uri, cwe: string, line: number, endLine?: number) => {
      const doc = await vscode.workspace.openTextDocument(uri);
      const relPath = vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/");
      const code = doc.getText();
      const snippet = lineTextAt(code, line, endLine ?? line);

      const choice = await confirmSuppression(cwe, snippet);
      if (choice === "cancel") return;
      if (choice === "explain") {
        await askAboutFinding(uri, cwe, line, output, undefined, "suppress");
        return;
      }

      await suppress(relPath, cwe, snippet, line);
      await recordActivity(context, {
        kind: "dismiss",
        file: relPath,
        cwe,
        detail: `line ${line}`,
      });
      output.appendLine(`[fp] dismissed ${cwe} at ${relPath}:${line} - ${snippet.trim()}`);

      // Refresh both diagnostic sets so the squiggle disappears immediately.
      const refreshed = filterDisabledCwes(
        filterSuppressed(analyzeCode(code, relPath), relPath, code)
      );
      updateDiagnostics(diagnostics, doc, refreshed);
      aiDiagnostics.set(
        uri,
        modelVulnsToDiagnostics(doc, filterSuppressedVulns(getModelResults(uri), relPath, code))
      );

      refreshDismissedButton();
      vscode.window.showInformationMessage(
        `Secure Assist: ${cwe} dismissed for this code. It will not be reported again unless the line changes.`
      );
    }
  );

  // Teacher agent: explains a finding conversationally. Backed by an external
  // API rather than the fine-tuned model, which only emits fix JSON.
  const askAgentCmd = vscode.commands.registerCommand(
    ASK_AGENT_COMMAND,
    async (
      uri: vscode.Uri,
      cwe: string,
      line?: number,
      fix?: { origin: string; replacement: string }
    ) => {
      await askAboutFinding(uri, cwe, line, output, fix);
    }
  );

  const openAgentCmd = vscode.commands.registerCommand("secure-assist.askQuestion", () => {
    AgentPanel.open(output);
  });

  // Always available: a question that is not tied to a finding — "is this fix
  // correct?", "why is this pattern unsafe?" — with the open file as context.
  const askButton = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 96);
  askButton.text = "$(comment-discussion) Ask";
  askButton.tooltip = "Secure Assist: ask the security assistant about this file";
  askButton.command = "secure-assist.askQuestion";
  askButton.show();

  const askAgentProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: "file" },
    new AskAgentProvider(),
    { providedCodeActionKinds: AskAgentProvider.kinds }
  );

  // Quick-fix provider: "Apply AI fix" on lines the model flagged.
  const aiFixProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: "file" },
    new AiFixProvider(),
    { providedCodeActionKinds: AiFixProvider.kinds }
  );

  // The same actions on the hover itself, so they are one click away and are
  // not mixed in with every other extension's quick fixes.
  const hoverProvider = vscode.languages.registerHoverProvider(
    { scheme: "file" },
    new SecureAssistHoverProvider()
  );
  const hoverActionCmd = registerHoverActions();

  context.subscriptions.push(
    startCmd,
    showStoredCmd,
    saveSub,
    openSub,
    changeSub,
    scanAiCmd,
    applyAiFixCmd,
    deepScanCmd,
    showFixesCmd,
    askAgentCmd,
    openAgentCmd,
    dismissCmd,
    showDismissedCmd,
    refreshStatusCmd,
    refreshHistoryCmd,
    refreshAiCmd,
    settingsCmd,
    settingsButton,
    askButton,
    dismissedButton,
    askAgentProvider,
    editorSub,
    scanButton,
    deepScanButton,
    fixesButton,
    aiFixProvider,
    hoverProvider,
    hoverActionCmd,
    fixesButtonSub,
    output,
    diagnostics,
    aiDiagnostics
  );

  // Dismissals and AI findings are both persisted, so the status bar must
  // reflect them on startup rather than only after the first editor switch —
  // no editor-change event fires for a document that is already open.
  refreshDismissedButton();
  refreshFixesButton();
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