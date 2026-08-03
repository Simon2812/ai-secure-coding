import * as vscode from "vscode";
import { ScanReport, scanWorkspace } from "./scanner";
import { buildReportHtml, renderCodeRows } from "./reportHtml";
import { scoreForFindings, projectScore } from "./score";
import { loadHistory, recordScan, ScanRecord } from "./history";
import {
  analyzeWithModel,
  getModelEndpoint,
  ModelFix,
  ModelVulnerability,
} from "../model/client";
import { analyzeCode } from "../analyzer/analyze";
import { correlateFindings } from "../model/correlation";
import { applyFixEdit } from "../model/aiFix";
import { renderFixDiff } from "../model/diffView";
import { getCweInfo } from "../model/cweCatalog";
import { containsOrigin } from "../model/originMatch";

/** Fixes returned by a "Verify with AI" request, keyed by the report's row id. */
type VerifiedFixes = Map<
  string,
  { uri: vscode.Uri; fixes: ModelFix[]; cwe: string; fileIndex: string; relPath: string }
>;

export class ReportPanel {
  private static current: ReportPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly output: vscode.OutputChannel;
  private readonly verified: VerifiedFixes = new Map();
  /** AI-only findings already injected into the report, so repeat verifies don't duplicate them. */
  private readonly aiOnlyShown = new Set<string>();
  private disposables: vscode.Disposable[] = [];
  private report: ScanReport;
  private readonly context: vscode.ExtensionContext;
  /** Scan history for this workspace, current scan included. */
  private history: ScanRecord[] = [];

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

    this.render();
    this.panel.webview.onDidReceiveMessage((msg) => this.onMessage(msg), null, this.disposables);
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
      "Secure Assist — Project Report",
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
    this.panel.webview.html = buildReportHtml(this.report, true, this.history);
  }

  private async onMessage(msg: any): Promise<void> {
    switch (msg?.type) {
      case "open":
        await this.openAt(msg.file, msg.line);
        break;
      case "verifyFile":
        await this.verifyFile(msg);
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
        message: "Could not resolve this file — re-scan the project.",
      });
      return;
    }

    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const code = doc.getText();
      const staticFindings = analyzeCode(code, msg.file);
      const result = await analyzeWithModel(code, staticFindings, getModelEndpoint());
      const vulns = result.vulnerabilities ?? [];

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

      this.panel.webview.postMessage({
        type: "fileVerified",
        index: msg.index,
        results,
        aiOnly,
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
    const applied = await applyFixEdit(entry.uri, fix);
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

    this.output.appendLine(
      `[report] fix applied to ${entry.relPath} — now ${findings.length} finding(s), ` +
        `file ${score}, project ${this.report.score}` +
        (doc.isDirty ? "  (unsaved — save the file to keep the change)" : "")
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
      const html = buildReportHtml(this.report, false, this.history);
      await vscode.workspace.fs.writeFile(target, Buffer.from(html, "utf-8"));
      this.output.appendLine(`[report] exported to ${target.fsPath}`);
    } catch (err: any) {
      const message = err?.message ?? String(err);
      vscode.window.showErrorMessage(`Secure Assist: export failed — ${message}`);
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
            `Secure Assist: could not open the report — it is at ${path}`
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
