import * as vscode from "vscode";
import { ScanReport, scanWorkspace } from "./scanner";
import { buildReportHtml } from "./reportHtml";
import { analyzeWithModel, getModelEndpoint, ModelFix } from "../model/client";
import { analyzeCode } from "../analyzer/analyze";
import { correlateFindings } from "../model/correlation";
import { previewAndApplyFix } from "../model/aiFix";

/** Fixes returned by a "Verify with AI" request, keyed by the report's row id. */
type VerifiedFixes = Map<string, { uri: vscode.Uri; fixes: ModelFix[]; cwe: string }>;

export class ReportPanel {
  private static current: ReportPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly output: vscode.OutputChannel;
  private readonly verified: VerifiedFixes = new Map();
  private disposables: vscode.Disposable[] = [];
  private report: ScanReport;

  private constructor(panel: vscode.WebviewPanel, report: ScanReport, output: vscode.OutputChannel) {
    this.panel = panel;
    this.report = report;
    this.output = output;

    this.render();
    this.panel.webview.onDidReceiveMessage((msg) => this.onMessage(msg), null, this.disposables);
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  static async show(output: vscode.OutputChannel): Promise<void> {
    const report = await ReportPanel.runScan();
    if (!report) return;

    if (ReportPanel.current) {
      ReportPanel.current.report = report;
      ReportPanel.current.verified.clear();
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
    ReportPanel.current = new ReportPanel(panel, report, output);
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
    this.panel.webview.html = buildReportHtml(this.report, true);
  }

  private async onMessage(msg: any): Promise<void> {
    switch (msg?.type) {
      case "open":
        await this.openAt(msg.file, msg.line);
        break;
      case "verify":
        await this.verify(msg);
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
          this.verified.clear();
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
   * Ask the model about one file and report whether it corroborates the static
   * finding the user clicked, along with any fixes it suggests for that CWE.
   */
  private async verify(msg: { id: string; file: string; line: number; cwe: string }): Promise<void> {
    const uri = this.fileUri(msg.file);
    if (!uri) return;

    try {
      const doc = await vscode.workspace.openTextDocument(uri);
      const code = doc.getText();
      const staticFindings = analyzeCode(code, msg.file);
      const result = await analyzeWithModel(code, staticFindings, getModelEndpoint());
      const vulns = result.vulnerabilities ?? [];

      // Confirmed when the model reports the same CWE overlapping this line.
      const target = staticFindings.filter(
        (f) => f.cweId === msg.cwe && f.line === msg.line
      );
      const correlation = correlateFindings(target, vulns);
      const confirmed = correlation.intersections.length > 0;

      const fixes = vulns
        .filter((v) => v.cwe === msg.cwe)
        .flatMap((v) => v.fixes ?? [])
        .filter((f) => code.includes(f.origin));

      this.verified.set(msg.id, { uri, fixes, cwe: msg.cwe });
      this.output.appendLine(
        `[report] verified ${msg.file}:${msg.line} ${msg.cwe} — ` +
          `${confirmed ? "confirmed" : "not confirmed"}, ${fixes.length} fix(es)`
      );

      this.panel.webview.postMessage({
        type: "verified",
        id: msg.id,
        file: msg.file,
        confirmed,
        fixes: fixes.map((f) => ({ origin: f.origin })),
      });
    } catch (err: any) {
      this.panel.webview.postMessage({
        type: "verifyFailed",
        id: msg.id,
        message: err?.message ?? String(err),
      });
    }
  }

  private async applyFix(msg: { id: string; fixIndex: number }): Promise<void> {
    const entry = this.verified.get(msg.id);
    if (!entry) return;
    const fix = entry.fixes[msg.fixIndex];
    if (!fix) return;
    // Reuses the same preview-then-apply flow as the editor quick fix.
    await previewAndApplyFix(entry.uri, fix, entry.cwe);
  }

  private async exportHtml(): Promise<void> {
    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {
      vscode.window.showWarningMessage("Secure Assist: open a folder to export the report.");
      return;
    }

    const target = vscode.Uri.joinPath(folder.uri, "security-report.html");
    try {
      const html = buildReportHtml(this.report, false);
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
