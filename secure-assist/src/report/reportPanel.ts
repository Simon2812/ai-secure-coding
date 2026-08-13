import * as vscode from "vscode";
import { ScanReport, scanWorkspace } from "./scanner";
import { buildReportHtml, renderCodeRows } from "./reportHtml";
import { scoreForFindings, projectScore } from "./score";
import {
  loadHistory,
  recordScan,
  clearHistory,
  ScanRecord,
  ActivityEvent,
  loadActivity,
  clearActivity,
  recordActivity,
} from "./history";
import {
  suppress,
  unsuppress,
  lineTextAt,
  listSuppressions,
  confirmSuppression,
  Suppression,
} from "./suppressions";
import { askAboutFinding } from "../agent/askAgent";
import {
  analyzeWithModel,
  getModelEndpoint,
  ModelFix,
  ModelVulnerability,
} from "../model/client";
import { analyzeCode } from "../analyzer/analyze";
import { correlateFindings } from "../model/correlation";
import {
  applyFixEdit,
  getModelResults,
  setModelResults,
  clearModelResults,
  onDidChangeModelResults,
} from "../model/aiFix";
import { appliedFixesFor, revertAppliedFix } from "../model/appliedFixes";
import { renderFixDiff } from "../model/diffView";
import { getCweInfo } from "../model/cweCatalog";
import { containsOrigin, groundVulnerabilities } from "../model/originMatch";
import { filterDisabledCwes, filterDisabledCweVulns } from "./settings";

/** Inclusive list of line numbers between two bounds. */
function range(from: number, to: number): number[] {
  const out: number[] = [];
  for (let i = from; i <= Math.max(from, to); i++) out.push(i);
  return out;
}

/** Fixes returned by a "Verify with AI" request, keyed by the report's row id. */
type VerifiedFixes = Map<
  string,
  { uri: vscode.Uri; fixes: ModelFix[]; cwe: string; fileIndex: string; relPath: string }
>;

export class ReportPanel {
  private static current: ReportPanel | undefined;

  /**
   * Re-read the scan history from storage and redraw.
   *
   * The panel caches the history so it can draw the trend without touching
   * storage on every render. When the settings panel clears it, that cache
   * has to be invalidated or the report keeps showing the old scan count.
   */
  static reloadHistory(context: vscode.ExtensionContext): void {
    const panel = ReportPanel.current;
    if (!panel) return;
    panel.history = loadHistory(context);
    panel.activity = loadActivity(context);
    panel.render();
  }

  private readonly panel: vscode.WebviewPanel;
  private readonly output: vscode.OutputChannel;
  private readonly verified: VerifiedFixes = new Map();
  /** AI-only findings already injected into the report, so repeat verifies don't duplicate them. */
  private readonly aiOnlyShown = new Set<string>();
  /** Files whose AI findings are currently on screen, so one that loses them
   *  still gets a payload telling the report to take its rows away. */
  private readonly aiFilesShown = new Set<string>();
  private disposables: vscode.Disposable[] = [];
  private report: ScanReport;
  private readonly context: vscode.ExtensionContext;
  /** Scan history for this workspace, current scan included. */
  private history: ScanRecord[] = [];
  /** Scans, fixes and dismissals, newest last. */
  private activity: ActivityEvent[] = [];

  private constructor(
    panel: vscode.WebviewPanel,
    report: ScanReport,
    output: vscode.OutputChannel,
    context: vscode.ExtensionContext,
    history: ScanRecord[]
  ) {
    this.panel = panel;
    this.report = report;
    this.output = output;
    this.context = context;
    this.history = history;
    this.activity = loadActivity(context);

    this.render();
    this.panel.webview.onDidReceiveMessage((msg) => this.onMessage(msg), null, this.disposables);
    // "Scan with AI" in the editor writes to the same store this report reads.
    // Without this the report only learns about those findings when it is next
    // rebuilt, so a file scanned while the report is open appeared to have
    // produced nothing. Both sides of the push are idempotent, so re-running it
    // only fills in what is missing.
    onDidChangeModelResults(
      () => {
        void this.showExistingAiFindings();
      },
      null,
      this.disposables
    );
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  static async show(
    output: vscode.OutputChannel,
    context: vscode.ExtensionContext
  ): Promise<void> {
    const report = await ReportPanel.runScan();
    if (!report) return;
    const history = await ReportPanel.remember(context, report);

    if (ReportPanel.current) {
      ReportPanel.current.report = report;
      ReportPanel.current.history = history;
      ReportPanel.current.verified.clear();
      ReportPanel.current.aiOnlyShown.clear();
      ReportPanel.current.render();
      ReportPanel.current.panel.reveal();
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      "secureAssistReport",
      "Secure Assist - Project Report",
      vscode.ViewColumn.One,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    ReportPanel.current = new ReportPanel(panel, report, output, context, history);
  }

  /** Persist this scan so the report can show a trend across sessions. */
  private static async remember(
    context: vscode.ExtensionContext,
    report: ScanReport
  ): Promise<ScanRecord[]> {
    await recordActivity(context, {
      kind: "scan",
      detail: `score ${report.score} · ${report.totalFindings} findings in ${report.scannedCount} files`,
    });
    return recordScan(context, {
      at: report.scannedAt.getTime(),
      score: report.score,
      findings: report.totalFindings,
      files: report.scannedCount,
    });
  }

  /** Scan the workspace behind a cancellable progress notification. */
  private static async runScan(): Promise<ScanReport | undefined> {
    if (!vscode.workspace.workspaceFolders?.length) {
      vscode.window.showWarningMessage("Secure Assist: open a folder to scan.");
      return undefined;
    }
    return vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "Secure Assist: scanning project",
        cancellable: true,
      },
      (progress, token) => scanWorkspace(progress, token)
    );
  }

  private render(): void {
    this.panel.webview.html = buildReportHtml(this.report, true, this.history, {
      activity: this.activity,
      suppressions: listSuppressions(),
    });
    // The injected AI findings are gone with the old DOM and have to be
    // pushed back in. The "already shown" guard is reset for the same reason.
    // The push itself waits for the webview's "ready" message: posting now
    // would land before its listener exists and be lost.
    this.aiOnlyShown.clear();
  }

  /**
   * Surface AI findings this workspace already has.
   *
   * "Scan with AI" in the editor and "Verify with AI" here write to the same
   * store, but the report is built from a static scan and would otherwise
   * show none of it — forcing the user to verify a file they had already
   * scanned. Findings the static analyzer also reported are left out, since
   * those rows are already on screen.
   */
  private async showExistingAiFindings(): Promise<void> {
    const payload: {
      path: string;
      aiOnly: unknown[];
      confirmed: unknown[];
      codeRows?: string;
      aiLineCount: number;
      hasAi: boolean;
    }[] = [];

    for (const file of this.report.files) {
      const stored = getModelResults(file.uri);
      // A file that has lost its AI findings still needs a payload, otherwise
      // its rows and highlighting would stay on screen after they are cleared.
      if (stored.length === 0 && !this.aiFilesShown.has(file.path)) continue;

      const correlation = correlateFindings(file.findings, stored);
      const aiOnly: unknown[] = [];
      const confirmed: unknown[] = [];

      // Static findings the model agreed with. These already have a row in
      // the report, so they get a verdict badge and the model's fix rather
      // than a second entry — otherwise a corroborated finding shows nothing
      // at all and the AI scan looks like it did nothing.
      correlation.confirmedStatic.forEach((staticIndex) => {
        const match = stored.find((v) => v.cwe === file.findings[staticIndex]?.cweId);
        const fixes = (match?.fixes ?? []).filter((f) =>
          containsOrigin(file.code ?? "", f.origin)
        );
        const fixId = `conf-${file.path}-${staticIndex}`;
        this.verified.set(fixId, {
          uri: file.uri,
          fixes,
          cwe: file.findings[staticIndex]?.cweId ?? "",
          fileIndex: "",
          relPath: file.path,
        });
        confirmed.push({
          staticIndex,
          fixId,
          fixCount: fixes.length,
          atLine: match?.start_line,
        });
      });

      stored.forEach((vuln, index) => {
        if (correlation.confirmedModel.has(index)) return;

        // Same id scheme the verify path uses, and the same index into the
        // stored results — so a later verify recognises these as already
        // shown instead of adding a second copy. The full current set is sent
        // every time: the report reconciles against it, which is what lets a
        // removed finding disappear. The webview skips ids already rendered.
        const id = `ai-${file.path}-${index}`;
        this.aiOnlyShown.add(id);

        const fixes = (vuln.fixes ?? []).filter((f) =>
          containsOrigin(file.code ?? "", f.origin)
        );
        this.verified.set(id, {
          uri: file.uri,
          fixes,
          cwe: vuln.cwe,
          fileIndex: "",
          relPath: file.path,
        });

        aiOnly.push({
          id,
          cwe: vuln.cwe,
          title: getCweInfo(vuln.cwe)?.title ?? "",
          line: vuln.start_line,
          fixCount: fixes.length,
        });
      });

      // The report's source view is built from the static scan alone, so lines
      // only the model flagged carry no marker until the code is re-rendered
      // with them. Verifying from inside the report already does this; a scan
      // started from the editor has to do it here or "See code" stays plain.
      const aiLines = stored.flatMap((v) =>
        v.start_line == null ? [] : range(v.start_line, v.end_line ?? v.start_line)
      );
      const codeRows = file.code
        ? renderCodeRows(file.code, file.findings.map((f) => f.line), aiLines)
        : undefined;

      if (stored.length) this.aiFilesShown.add(file.path);
      else this.aiFilesShown.delete(file.path);

      payload.push({
        path: file.path,
        aiOnly,
        confirmed,
        codeRows,
        // Drives the two-colour key above the source: shown once the model has
        // marked something here, removed again when it no longer has.
        aiLineCount: new Set(aiLines).size,
        // Whether this file has anything to clear.
        hasAi: stored.length > 0,
      });
    }

    if (payload.length) {
      this.panel.webview.postMessage({ type: "existingAi", files: payload });
    }
  }

  private async onMessage(msg: any): Promise<void> {
    switch (msg?.type) {
      case "ready":
        // The webview can receive messages now — restore anything the
        // extension already knows that is not part of the static HTML.
        await this.showExistingAiFindings();
        break;
      case "open":
        await this.openAt(msg.file, msg.line);
        break;
      case "openFile":
        await this.openFileInWorkspace(msg.file, msg.line);
        break;
      case "clearFileAi":
        await this.clearAiForFile(msg.file);
        break;
      case "clearHistory":
        await this.clearScanHistory();
        break;
      case "clearActivityLog":
      case "clearActivity":
        await this.clearActivityLog();
        break;
      case "revertFix":
        await this.revertFix(msg.file, msg.idx);
        break;
      case "verifyFile":
        await this.verifyFile(msg);
        break;
      case "dismiss":
        await this.dismissFinding(msg);
        break;
      case "restore":
        await this.restoreFinding(msg);
        break;
      case "previewFix":
        this.previewFix(msg);
        break;
      case "fix":
        await this.applyFix(msg);
        break;
      case "export":
        await this.exportHtml();
        break;
      case "rescan": {
        const report = await ReportPanel.runScan();
        if (report) {
          this.report = report;
          this.history = await ReportPanel.remember(this.context, report);
          this.verified.clear();
          this.aiOnlyShown.clear();
          this.render();
        }
        break;
      }
    }
  }

  private fileUri(relPath: string): vscode.Uri | undefined {
    return this.report.files.find((f) => f.path === relPath)?.uri;
  }

  private async openAt(relPath: string, line: number): Promise<void> {
    const uri = this.fileUri(relPath);
    if (!uri) return;
    const doc = await vscode.workspace.openTextDocument(uri);
    const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.Beside);
    const pos = new vscode.Position(Math.max(0, line - 1), 0);
    editor.selection = new vscode.Selection(pos, pos);
    editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
  }

  /** Delete the activity log — scans, fixes, suppressions and reverts. */
  private async clearActivityLog(): Promise<void> {
    const ok = await vscode.window.showWarningMessage(
      "Clear the activity log for this workspace?",
      {
        modal: true,
        detail:
          "The record of scans, applied fixes, suppressions and reverts is deleted. " +
          "Findings, scores and scan history are not affected. This cannot be undone.",
      },
      "Clear log"
    );
    if (ok !== "Clear log") return;

    await clearActivity(this.context);
    this.activity = [];
    this.render();
  }

  /**
   * Undo an applied fix from the report.
   *
   * The file is re-analysed afterwards so the score, the finding list and the
   * counts reflect the restored code — reverting the text alone would leave
   * the report claiming a file is cleaner than it is.
   */
  private async revertFix(relPath: string, index: number): Promise<void> {
    const uri = this.fileUri(relPath);
    const entry = appliedFixesFor(relPath)[index];
    if (!uri || !entry) return;

    const restored = await revertAppliedFix(entry, uri);
    if (!restored) {
      vscode.window.showWarningMessage(
        `Secure Assist: could not revert the ${entry.cwe} fix in ${relPath} - the code has been edited since.`
      );
      this.render();
      return;
    }

    setModelResults(uri, [...getModelResults(uri), restored]);

    // Re-analyse so the report's findings and score match the file again.
    const doc = await vscode.workspace.openTextDocument(uri);
    const code = doc.getText();
    const findings = filterDisabledCwes(analyzeCode(code, relPath));
    const file = this.report.files.find((f) => f.path === relPath);
    if (file) {
      file.findings = findings;
      file.code = code;
      file.score = scoreForFindings(findings);
    }
    this.report.totalFindings = this.report.files.reduce(
      (n, f) => n + f.findings.length,
      0
    );
    this.report.score = projectScore(this.report.files.map((f) => f.score));

    await recordActivity(this.context, {
      kind: "restore",
      file: relPath,
      cwe: entry.cwe,
      detail: `reverted AI fix at line ${entry.line}`,
    });
    this.activity = loadActivity(this.context);

    this.output.appendLine(`[report] reverted ${entry.cwe} fix in ${relPath}`);
    await vscode.commands.executeCommand("secure-assist.internal.refreshStatusBar");
    this.render();
  }

  /**
   * Delete the recorded scan history for this workspace.
   *
   * The current report stays on screen — this removes the record of previous
   * scans that drives the trend line and the scan counter, not the findings
   * being displayed.
   */
  /**
   * Discard one file's AI findings.
   *
   * Settings can only clear the whole workspace, which is too blunt when a
   * single file's scan is stale or wrong. This goes through the same store the
   * report listens to, so the rows, the source highlighting and the colour key
   * come off on their own rather than needing their own removal code.
   */
  private async clearAiForFile(relPath: string): Promise<void> {
    const file = this.report.files.find((f) => f.path === relPath);
    if (!file) return;

    const count = getModelResults(file.uri).length;
    if (count === 0) return;

    const ok = await vscode.window.showWarningMessage(
      `Discard the AI findings for ${relPath}?`,
      {
        modal: true,
        detail:
          `${count} finding${count === 1 ? "" : "s"} and any fixes suggested for them are ` +
          "removed for this file only. Static analyzer findings are not affected and other " +
          "files keep theirs. Recovering them means scanning this file with AI again.",
      },
      "Discard"
    );
    if (ok !== "Discard") return;

    clearModelResults(file.uri);

    // The rows are gone, so the fixes registered against them are dead entries.
    for (const key of [...this.verified.keys()]) {
      if (key.startsWith(`ai-${relPath}-`) || key.startsWith(`conf-${relPath}-`)) {
        this.verified.delete(key);
      }
    }
    for (const id of [...this.aiOnlyShown]) {
      if (id.startsWith(`ai-${relPath}-`)) this.aiOnlyShown.delete(id);
    }

    await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");
    this.output.appendLine(`[report] cleared ${count} AI finding(s) for ${relPath}`);
  }

  private async clearScanHistory(): Promise<void> {
    const ok = await vscode.window.showWarningMessage(
      "Clear the scan history for this workspace?",
      {
        modal: true,
        detail:
          "The recorded scans, their scores and the trend line are deleted, and " +
          "the scan counter resets to zero. The findings currently shown are not " +
          "affected. This cannot be undone.",
      },
      "Clear history"
    );
    if (ok !== "Clear history") return;

    await clearHistory(this.context);

    // Keep the scan on screen as the new baseline. Clearing to nothing means
    // the trend needs two further scans before it reappears, which reads as
    // the graph having been destroyed rather than reset.
    this.history = await recordScan(this.context, {
      at: this.report.scannedAt.getTime(),
      score: this.report.score,
      findings: this.report.totalFindings,
      files: this.report.scannedCount,
    });
    this.render();
  }

  /**
   * Open the real file for editing, rather than the report's read-only copy.
   *
   * Differs from openAt in that it takes focus and reuses the editor group the
   * user was last in: this is "take me to the file", not "show me the line
   * beside the report".
   */
  private async openFileInWorkspace(relPath: string, line: number): Promise<void> {
    const uri = this.fileUri(relPath);
    if (!uri) {
      void vscode.window.showWarningMessage(
        `Could not locate ${relPath} in the workspace. It may have been moved or deleted since the scan.`
      );
      return;
    }
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const editor = await vscode.window.showTextDocument(doc, {
        viewColumn: vscode.ViewColumn.One,
        preview: false,
        preserveFocus: false,
      });
      const pos = new vscode.Position(Math.max(0, line - 1), 0);
      editor.selection = new vscode.Selection(pos, pos);
      editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
    } catch (err) {
      void vscode.window.showErrorMessage(
        `Could not open ${relPath}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  /**
   * Run the model once over a whole file.
   *
   * A single inference covers every finding in the file, so verification is a
   * per-file action: each static finding gets a verdict, and anything the model
   * reports that the analyzer missed is returned as an AI-only finding. Clean
   * files are worth verifying too — that is where the model can add detections.
   */
  private async verifyFile(msg: { index: string; file: string }): Promise<void> {
    const uri = this.fileUri(msg.file);
    if (!uri) {
      // Always answer the webview — an unanswered request leaves its spinner
      // running forever with no way for the user to tell what went wrong.
      this.output.appendLine(`[report] verify failed: unknown file "${msg.file}"`);
      this.panel.webview.postMessage({
        type: "verifyFailed",
        index: msg.index,
        message: "Could not resolve this file - re-scan the project.",
      });
      return;
    }

    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const code = doc.getText();
      const staticFindings = filterDisabledCwes(analyzeCode(code, msg.file));
      const result = await analyzeWithModel(code, staticFindings, getModelEndpoint());

      // Drop findings the model could not tie to code actually in this file.
      const { grounded, discarded } = groundVulnerabilities(
        result.vulnerabilities ?? [],
        code
      );
      for (const d of discarded) {
        this.output.appendLine(
          `[report] ignored ${d.cwe} in ${msg.file}: origin not present in the file`
        );
      }

      // The model is a general code model and reports weaknesses outside the
      // ten this tool covers. Showing those would claim coverage the analyzer
      // does not have and cannot corroborate, so they are dropped here.
      // Line order, so AI-only findings read down the file like the static
      // ones rather than in whatever order the model happened to list them.
      const vulns = filterDisabledCweVulns(grounded).sort(
        (a, b) =>
          (a.start_line ?? Number.MAX_SAFE_INTEGER) -
          (b.start_line ?? Number.MAX_SAFE_INTEGER)
      );
      // Share the results with the rest of the extension. Without this a
      // verification done here is invisible to the editor squiggles, the
      // status bar and the fixes panel, and the user has to scan the same
      // file a second time to get them.
      setModelResults(uri, vulns);

      const outOfScope = grounded.length - vulns.length;
      if (outOfScope > 0) {
        this.output.appendLine(
          `[report] ignored ${outOfScope} model finding${outOfScope === 1 ? "" : "s"} in ${msg.file}: CWE outside the supported set`
        );
      }

      const correlation = correlateFindings(staticFindings, vulns);

      // Only findings the model actually corroborated are reported back. A
      // finding it did not confirm gets no verdict and no fix — the two tools
      // detect different things, so silence from one is not a judgement on the
      // other, and offering a fix the model never proposed for it would be wrong.
      const results = staticFindings.flatMap((finding, i) => {
        if (!correlation.confirmedStatic.has(i)) return [];

        // Take fixes only from the model findings that matched *this* one.
        const matches = correlation.intersections.filter((x) => x.staticIndex === i);
        const fixes = matches
          .flatMap((x) => vulns[x.modelIndex]?.fixes ?? [])
          .filter((f) => containsOrigin(code, f.origin));

        // When the model located the same issue somewhere else in the file, say
        // where — the two tools legitimately disagree about a flaw's "location".
        const elsewhere = matches.find((x) => x.reason === "same_cwe_elsewhere_in_file");
        const atLine = elsewhere ? vulns[elsewhere.modelIndex]?.start_line : undefined;

        const id = `${msg.index}-${i}`;
        this.verified.set(id, {
          uri,
          fixes,
          cwe: finding.cweId,
          fileIndex: msg.index,
          relPath: msg.file,
        });
        return [{ id, fixCount: fixes.length, atLine }];
      });

      const aiOnly = this.collectAiOnly(uri, msg.file, code, staticFindings, vulns, msg.index);

      this.output.appendLine(
        `[report] verified ${msg.file}: ${results.length}/${staticFindings.length} confirmed, ` +
          `${aiOnly.length} AI-only`
      );

      // Re-render the file's source so lines the model flagged get their own
      // colour alongside the static analyzer's.
      const aiLines = vulns
        .flatMap((v) =>
          v.start_line == null
            ? []
            : range(v.start_line, v.end_line ?? v.start_line)
        );

      this.panel.webview.postMessage({
        type: "fileVerified",
        index: msg.index,
        results,
        aiOnly,
        codeRows: renderCodeRows(code, staticFindings.map((f) => f.line), aiLines),
        aiLineCount: new Set(aiLines).size,
      });
    } catch (err: any) {
      this.panel.webview.postMessage({
        type: "verifyFailed",
        index: msg.index,
        message: err?.message ?? String(err),
      });
    }
  }

  /**
   * Model findings for a file that the static analyzer did not report.
   *
   * Each one is registered under its own id so the report can offer the same
   * "Apply fix" flow for it as for a static finding.
   */
  private collectAiOnly(
    uri: vscode.Uri,
    relPath: string,
    code: string,
    staticFindings: ReturnType<typeof analyzeCode>,
    vulns: ModelVulnerability[],
    fileIndex: string
  ): { id: string; cwe: string; title: string; line?: number; fixCount: number }[] {
    const correlation = correlateFindings(staticFindings, vulns);
    const results: { id: string; cwe: string; title: string; line?: number; fixCount: number }[] = [];

    vulns.forEach((vuln, index) => {
      if (correlation.confirmedModel.has(index)) return; // the analyzer found it too

      const id = `ai-${relPath}-${index}`;
      if (this.aiOnlyShown.has(id)) return; // already added to the report
      this.aiOnlyShown.add(id);

      const fixes = (vuln.fixes ?? []).filter((f) => containsOrigin(code, f.origin));
      this.verified.set(id, { uri, fixes, cwe: vuln.cwe, fileIndex, relPath });

      results.push({
        id,
        cwe: vuln.cwe,
        title: getCweInfo(vuln.cwe)?.title ?? "",
        line: vuln.start_line,
        fixCount: fixes.length,
      });
      this.output.appendLine(
        `[report] AI-only finding in ${relPath}: ${vuln.cwe} at line ${vuln.start_line ?? "?"}`
      );
    });

    return results;
  }

  /**
   * Record a finding as a false positive and drop it from the in-memory report
   * so the scores reflect the dismissal without needing a re-scan.
   */
  private async dismissFinding(msg: {
    file: string;
    cwe: string;
    line: number;
  }): Promise<void> {
    const stored = this.report.files.find((f) => f.path === msg.file);
    if (!stored?.code) return;

    const snippet = lineTextAt(stored.code, msg.line);
    const choice = await confirmSuppression(msg.cwe, snippet);
    if (choice !== "suppress") {
      // Re-enable the button and undo the row's dimmed state.
      this.panel.webview.postMessage({ type: "dismissCancelled", id: `${msg.file}:${msg.line}` });
      if (choice === "explain") {
        await askAboutFinding(stored.uri, msg.cwe, msg.line, this.output, undefined, "suppress");
      }
      return;
    }

    await suppress(msg.file, msg.cwe, snippet, msg.line);
    this.activity = await recordActivity(this.context, {
      kind: "dismiss",
      file: msg.file,
      cwe: msg.cwe,
      detail: `line ${msg.line}`,
    });
    this.output.appendLine(`[fp] dismissed ${msg.cwe} at ${msg.file}:${msg.line}`);
    // Keep the per-file status-bar counter in step with dismissals made here.
    await vscode.commands.executeCommand("secure-assist.internal.refreshStatusBar");

    stored.findings = stored.findings.filter(
      (f) => !(f.cweId === msg.cwe && f.line === msg.line)
    );
    stored.score = scoreForFindings(stored.findings);
    this.report.score = projectScore(this.report.files.map((f) => f.score));
    this.report.cleanCount = this.report.files.filter((f) => f.findings.length === 0).length;
    this.report.totalFindings = this.report.files.reduce((n, f) => n + f.findings.length, 0);

    this.panel.webview.postMessage({
      type: "dismissed",
      score: stored.score,
      projectScore: this.report.score,
      cleanCount: this.report.cleanCount,
      scannedCount: this.report.scannedCount,
      file: msg.file,
    });
  }

  /**
   * Undo a false-positive dismissal. The finding is not re-inserted into the
   * current report — it reappears on the next scan, when the analyzer looks at
   * that code again.
   */
  private async restoreFinding(msg: {
    file: string;
    cwe: string;
    code: string;
  }): Promise<void> {
    await unsuppress(msg.file, msg.cwe, msg.code);
    await vscode.commands.executeCommand("secure-assist.internal.refreshStatusBar");
    this.activity = await recordActivity(this.context, {
      kind: "restore",
      file: msg.file,
      cwe: msg.cwe,
    });
    this.output.appendLine(`[fp] restored ${msg.cwe} in ${msg.file}`);
    this.panel.webview.postMessage({ type: "restored", file: msg.file, cwe: msg.cwe });
  }

  /**
   * Render the change inline in the report rather than in a modal dialog, so
   * the diff is reviewed in the same place as the finding it belongs to.
   */
  private previewFix(msg: { id: string; fixIndex: number }): void {
    const entry = this.verified.get(msg.id);
    const fix = entry?.fixes[msg.fixIndex];
    if (!fix) return;
    this.panel.webview.postMessage({
      type: "fixPreview",
      id: msg.id,
      fixIndex: msg.fixIndex,
      cwe: entry!.cwe,
      diffHtml: renderFixDiff(fix, true),
    });
  }

  private async applyFix(msg: { id: string; fixIndex: number }): Promise<void> {
    const entry = this.verified.get(msg.id);
    if (!entry) return;
    const fix = entry.fixes[msg.fixIndex];
    if (!fix) return;

    // The report already showed the diff inline, so no second confirmation.
    const applied = await applyFixEdit(entry.uri, fix, undefined, entry.cwe);
    if (!applied) return;

    // Re-analyze the edited file so the report reflects the new state rather
    // than the snapshot it was rendered from.
    const doc = await vscode.workspace.openTextDocument(entry.uri);
    const code = doc.getText();
    const findings = analyzeCode(code, entry.relPath);
    const score = scoreForFindings(findings);

    // Keep the in-memory report in sync for re-export and later verifies.
    const stored = this.report.files.find((f) => f.path === entry.relPath);
    if (stored) {
      stored.findings = findings;
      stored.score = score;
      stored.code = code;
    }
    // Recompute the project-level figures so the header reflects the fix.
    this.report.score = projectScore(this.report.files.map((f) => f.score));
    this.report.cleanCount = this.report.files.filter((f) => f.findings.length === 0).length;
    this.report.totalFindings = this.report.files.reduce((n, f) => n + f.findings.length, 0);

    this.activity = await recordActivity(this.context, {
      kind: "fix",
      file: entry.relPath,
      cwe: entry.cwe,
      detail: `file score ${score} · project ${this.report.score}`,
    });

    this.output.appendLine(
      `[report] fix applied to ${entry.relPath} - now ${findings.length} finding(s), ` +
        `file ${score}, project ${this.report.score}` +
        (doc.isDirty ? "  (unsaved - save the file to keep the change)" : "")
    );

    this.panel.webview.postMessage({
      type: "fixApplied",
      id: msg.id,
      fileIndex: entry.fileIndex,
      score,
      findingCount: findings.length,
      projectScore: this.report.score,
      cleanCount: this.report.cleanCount,
      scannedCount: this.report.scannedCount,
      codeRows: renderCodeRows(code, findings.map((f) => f.line)),
    });
  }

  private async exportHtml(): Promise<void> {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showWarningMessage("Secure Assist: open a folder to export the report.");
      return;
    }

    const target = vscode.Uri.joinPath(folder.uri, "security-report.html");
    try {
      const html = buildReportHtml(this.report, false, this.history, {
        activity: this.activity,
        suppressions: listSuppressions(),
      });
      await vscode.workspace.fs.writeFile(target, Buffer.from(html, "utf-8"));
      this.output.appendLine(`[report] exported to ${target.fsPath}`);
    } catch (err: any) {
      const message = err?.message ?? String(err);
      vscode.window.showErrorMessage(`Secure Assist: export failed - ${message}`);
      this.output.appendLine(`[report] export failed: ${message}`);
      return;
    }

    const choice = await vscode.window.showInformationMessage(
      `Secure Assist: report exported to ${vscode.workspace.asRelativePath(target)}`,
      "Open in editor",
      "Open in browser"
    );
    if (choice === "Open in editor") {
      const doc = await vscode.workspace.openTextDocument(target);
      await vscode.window.showTextDocument(doc);
    } else if (choice === "Open in browser") {
      // `env.openExternal` fails on Windows for file:// URIs, so hand the path
      // to the OS and let it pick the default browser.
      const { exec } = await import("child_process");
      const path = target.fsPath;
      const command =
        process.platform === "win32"
          ? `start "" "${path}"`
          : process.platform === "darwin"
          ? `open "${path}"`
          : `xdg-open "${path}"`;
      exec(command, { shell: process.platform === "win32" ? "cmd.exe" : undefined }, (err) => {
        if (err) {
          vscode.window.showErrorMessage(
            `Secure Assist: could not open the report - it is at ${path}`
          );
        }
      });
    }
  }

  private dispose(): void {
    ReportPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) this.disposables.pop()?.dispose();
  }
}
