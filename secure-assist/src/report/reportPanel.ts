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
  filterSuppressed,
  onDidChangeSuppressions,
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
import { appliedFixesIn, revertAppliedFix } from "../model/appliedFixes";
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
  /** Set while a re-scan is running, so events it causes do not start another. */
  private rescanning = false;
  /**
   * Set while this panel is applying or reverting a fix.
   *
   * Those operations change the model results before the report's own snapshot
   * has caught up, so a reconcile fired in between compares new findings
   * against stale ones and wrongly strips the verdict off untouched rows. The
   * reconcile is run once at the end instead, when both agree again.
   */
  private mutatingFix = false;
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
        if (this.mutatingFix) return; // reconciled at the end of the operation
        void this.showExistingAiFindings();
      },
      null,
      this.disposables
    );
    // Dismissing or restoring a finding anywhere - the quick fix, the dismissed
    // panel, the settings screen - changes what this report should show. It
    // filters suppressed findings out of its own counts, so without this a
    // restored finding stayed missing until the next scan, and the dismissed
    // section never appeared at all.
    onDidChangeSuppressions(
      () => this.refreshForSuppressions(),
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
    //
    // `verified` is deliberately NOT cleared here. Only the AI-only and
    // confirmed rows are re-registered by that push; fixes registered by
    // "Verify with AI" are not, so clearing left their buttons pointing at
    // entries that no longer existed and Apply did nothing at all.
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

    // Set when a file that was showing AI results now has none. Clearing them
    // does not just remove rows: the verdict badges on static findings have to
    // come off too, and those are keyed by position, so a file whose findings
    // shifted would have the wrong badges stripped. Rebuilding from the
    // snapshot avoids the question entirely, and costs no re-scan.
    const cleared: string[] = [];

    for (const file of this.report.files) {
      const stored = getModelResults(file.uri);
      // A file that has lost its AI findings still needs a payload, otherwise
      // its rows and highlighting would stay on screen after they are cleared.
      //
      // `aiFilesShown` only records what this method itself pushed. Rows added
      // by "Verify with AI" register their fixes and nothing else, so a file
      // verified from inside the report is absent from that set: keying off it
      // alone left the verdict badges on screen after the findings behind them
      // were discarded. Anything registered against the file counts as shown.
      const wasShowingAi =
        this.aiFilesShown.has(file.path) ||
        [...this.verified.values()].some((v) => v.relPath === file.path);
      if (stored.length === 0 && !wasShowingAi) continue;
      if (stored.length === 0) cleared.push(file.path);

      const correlation = correlateFindings(file.findings, stored);
      const aiOnly: unknown[] = [];
      const confirmed: unknown[] = [];

      // Static findings the model agreed with. These already have a row in
      // the report, so they get a verdict badge and the model's fix rather
      // than a second entry — otherwise a corroborated finding shows nothing
      // at all and the AI scan looks like it did nothing.
      correlation.confirmedStatic.forEach((staticIndex) => {
        // Which model findings matched *this* static one. Searching the store
        // for the first entry with the same CWE tied every row of a given CWE
        // to the same model finding: two SQL injections both reported the same
        // line and offered the same fix, and applying one appeared to
        // un-confirm the other because that single entry had gone.
        const matches = correlation.intersections.filter((x) => x.staticIndex === staticIndex);
        const fixes = matches
          .flatMap((x) => stored[x.modelIndex]?.fixes ?? [])
          .filter((f) => containsOrigin(file.code ?? "", f.origin));

        // Only say "at line N" when the model put the same issue somewhere
        // else in the file; agreeing on the line needs no explanation.
        const elsewhere = matches.find((x) => x.reason === "same_cwe_elsewhere_in_file");
        const atLine = elsewhere ? stored[elsewhere.modelIndex]?.start_line : undefined;

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
          atLine,
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

    if (cleared.length) {
      // AI findings were discarded somewhere else - the status bar, the editor,
      // the settings screen - while this report was open. Same reasoning as the
      // clear button: re-scan rather than try to unpick the rows in place. The
      // scan clears all three registries, so the rebuild's own call back into
      // here finds nothing shown and stops instead of looping.
      this.output.appendLine(
        `[report] AI findings cleared for ${cleared.join(", ")} - re-scanning`
      );
      await this.rescan();
      return;
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
      case "rescan":
        await this.rescan();
        break;
    }
  }

  /**
   * Re-scan the project and rebuild the report.
   *
   * Also used whenever AI findings are discarded. Reconciling that in place
   * means removing rows, un-badging the static findings behind them and
   * dropping their registered fixes, all keyed by a position that the rest of
   * the report has already moved on from - and it kept leaving verdict badges
   * on screen for findings that no longer existed. A scan is the state the
   * report is meant to show, so it is taken again rather than approximated.
   */
  private async rescan(): Promise<void> {
    if (this.rescanning) return;
    this.rescanning = true;
    try {
      const report = await ReportPanel.runScan();
      if (!report) return;
      this.report = report;
      this.history = await ReportPanel.remember(this.context, report);
      this.verified.clear();
      this.aiOnlyShown.clear();
      this.aiFilesShown.clear();
      this.render();
    } finally {
      this.rescanning = false;
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
    if (!uri) return;

    // Index against the same filtered list the report rendered, or a hidden
    // stale entry would shift the rows and revert the wrong change.
    const document = await vscode.workspace.openTextDocument(uri);
    const entry = appliedFixesIn(relPath, document.getText())[index];
    if (!entry) return;

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
    // Suppressions are filtered here as well as in the workspace scan: without
    // it a dismissed finding stayed hidden in the deep scan but came back the
    // moment a fix was applied or reverted in the same file.
    const findings = filterDisabledCwes(
      filterSuppressed(analyzeCode(code, relPath), relPath, code)
    );
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
    // The finding has been put back into the store, but this panel holds no
    // diagnostics collection, so without this its squiggle stayed missing.
    await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");
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
    // Matched on the file rather than on an id prefix: "Verify with AI" numbers
    // its rows by file index, so a prefix match missed exactly the rows this
    // panel had put the verdict badges on.
    let dropped = 0;
    for (const [key, entry] of [...this.verified]) {
      if (entry.relPath === relPath) {
        this.verified.delete(key);
        dropped++;
      }
    }
    for (const id of [...this.aiOnlyShown]) {
      if (id.startsWith(`ai-${relPath}-`)) this.aiOnlyShown.delete(id);
    }
    this.aiFilesShown.delete(relPath);

    await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");
    this.output.appendLine(
      `[report] cleared ${count} AI finding(s) for ${relPath}, dropped ${dropped} registered row(s)`
    );

    await this.rescan();
  }

  /**
   * Re-apply the suppression list to the scan already held in memory.
   *
   * Re-analysing from each file's cached source rather than re-reading the
   * workspace: the text has not changed, only which findings are allowed to be
   * reported, so this costs a parse per file and no disk access.
   */
  private refreshForSuppressions(): void {
    for (const file of this.report.files) {
      if (file.code == null) continue;
      file.findings = filterDisabledCwes(
        filterSuppressed(analyzeCode(file.code, file.path), file.path, file.code)
      );
      file.score = scoreForFindings(file.findings);
    }
    this.report.score = projectScore(this.report.files.map((f) => f.score));
    this.report.cleanCount = this.report.files.filter((f) => f.findings.length === 0).length;
    this.report.totalFindings = this.report.files.reduce((n, f) => n + f.findings.length, 0);
    this.render();
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

    // Writing the results below fires the store's change event, which would
    // have this panel reconcile against a half-finished verification and, for a
    // file whose findings were previously cleared, rebuild the report out from
    // under the update this method is about to post. The verification reports
    // its own results when it is done.
    this.mutatingFix = true;
    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const code = doc.getText();
      // Same reasoning as the re-analysis after a fix: a dismissed finding must
      // not reappear just because the file was verified with the model.
      const staticFindings = filterDisabledCwes(
        filterSuppressed(analyzeCode(code, msg.file), msg.file, code)
      );
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
      // Storing the results is not enough to put squiggles in the editor: the
      // diagnostic collection is rebuilt from the store on demand, and nothing
      // else does it for us here. Without this the fixes button counted the new
      // findings while the file itself showed nothing, so verifying from the
      // report looked like it had only half worked.
      await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");

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
    } finally {
      this.mutatingFix = false;
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
    if (!fix) {
      // Returning silently here made a dead button indistinguishable from a
      // working one: nothing happened and nothing said why.
      this.output.appendLine(
        `[report] no fix registered for "${msg.id}" (index ${msg.fixIndex}). ` +
          `entry=${entry ? `found, ${entry.fixes.length} fix(es)` : "missing"}. ` +
          `known ids: ${[...this.verified.keys()].join(", ") || "(none)"}`
      );
      this.panel.webview.postMessage({ type: "fixUnavailable", id: msg.id });
      return;
    }
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
    this.mutatingFix = true;
    let applied = false;
    try {
      applied = await applyFixEdit(entry.uri, fix, undefined, entry.cwe);
    } finally {
      this.mutatingFix = false;
    }
    if (!applied) return;

    // This panel holds no diagnostics collection, so the AI squiggles on the
    // rewritten lines were left behind. Rebuilding from the store clears them.
    await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");

    // Re-analyze the edited file so the report reflects the new state rather
    // than the snapshot it was rendered from.
    const doc = await vscode.workspace.openTextDocument(entry.uri);
    const code = doc.getText();
    // Same filters the workspace scan applies, so a dismissed finding or a
    // switched-off category does not reappear just because a fix was applied.
    const findings = filterDisabledCwes(
      filterSuppressed(analyzeCode(code, entry.relPath), entry.relPath, code)
    );
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

    // Re-render rather than patching the rendered rows, the way reverting
    // already does.
    //
    // Re-analysing drops the fixed finding, so every finding below it shifts up
    // one index while the rendered rows keep the indices they were built with.
    // Any update keyed on position is wrong from that point on, which is what
    // stripped the verdict off findings that were never touched. Rebuilding
    // from the snapshot regenerates the ids in step, brings in the applied-fix
    // row with its Revert, and costs nothing: the analysis is already done and
    // held in memory, so this is not a re-scan.
    this.render();
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
