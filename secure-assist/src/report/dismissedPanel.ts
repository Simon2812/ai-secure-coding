import * as vscode from "vscode";
import {
  listSuppressions,
  unsuppress,
  onDidChangeSuppressions,
  Suppression,
} from "./suppressions";
import { getCweInfo } from "../model/cweCatalog";
import { PALETTE } from "./reportHtml";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * The findings dismissed as false positives in one file.
 *
 * The project report lists dismissals across the whole workspace; this is the
 * view for the file being edited, so a developer can see and undo what they
 * silenced here without opening a project-wide scan.
 */
export class DismissedPanel {
  private static current: DismissedPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  /** Re-runs analysis on a file so a restored finding reappears immediately. */
  private readonly refresh: (uri: vscode.Uri) => Promise<void>;
  private uri: vscode.Uri;
  private disposables: vscode.Disposable[] = [];
  /** Set while this panel is the one changing the list, so it keeps its own
   *  "removed" confirmation instead of re-rendering the row away underneath. */
  private removingHere = false;

  private constructor(
    panel: vscode.WebviewPanel,
    uri: vscode.Uri,
    refresh: (uri: vscode.Uri) => Promise<void>
  ) {
    this.panel = panel;
    this.uri = uri;
    this.refresh = refresh;
    this.render();
    this.panel.webview.onDidReceiveMessage((m) => this.onMessage(m), null, this.disposables);
    // A finding dismissed elsewhere - the quick fix, the report, the settings
    // screen - must show up here without the panel being closed and reopened.
    onDidChangeSuppressions(
      () => {
        if (!this.removingHere) this.render();
      },
      null,
      this.disposables
    );
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  static show(uri: vscode.Uri, refresh: (uri: vscode.Uri) => Promise<void>): void {
    if (DismissedPanel.current) {
      DismissedPanel.current.uri = uri;
      DismissedPanel.current.render();
      DismissedPanel.current.panel.reveal(vscode.ViewColumn.Beside, true);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "secureAssistDismissed",
      "Secure Assist - Dismissed",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      { enableScripts: true, retainContextWhenHidden: true }
    );
    DismissedPanel.current = new DismissedPanel(panel, uri, refresh);
  }

  /** Dismissals recorded for the file currently shown. */
  private forThisFile(): Suppression[] {
    const relPath = vscode.workspace.asRelativePath(this.uri, false).replace(/\\/g, "/");
    return listSuppressions()
      .filter((s) => s.file === relPath)
      .sort((a, b) => b.at - a.at);
  }

  private render(): void {
    const relPath = vscode.workspace.asRelativePath(this.uri, false).replace(/\\/g, "/");
    const items = this.forThisFile();
    this.panel.title = `Dismissed - ${relPath.split("/").pop()}`;

    const body = items.length
      ? items
          .map((s, i) => {
            const info = getCweInfo(s.cwe);
            const title = info ? `${s.cwe} - ${info.title}` : s.cwe;
            return `
            <div class="row" id="row-${i}">
              <div class="head">
                <span class="cwe">${escapeHtml(title)}</span>
                ${s.line ? `<span class="loc">was line ${s.line}</span>` : ""}
                <span class="when">${new Date(s.at).toLocaleString()}</span>
              </div>
              <pre class="code">${escapeHtml(s.code)}</pre>
              <div class="actions">
                <button class="restore" data-index="${i}">Remove suppression</button>
                <span class="state" id="state-${i}"></span>
              </div>
            </div>`;
          })
          .join("")
      : `<p class="empty">Nothing has been dismissed in this file.</p>`;

    this.panel.webview.html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><style>${PALETTE}${STYLES}</style></head>
<body>
  <h1>Dismissed findings</h1>
  <p class="sub">${escapeHtml(relPath)} · ${items.length} dismissed</p>
  ${items.length ? `<p class="note">While a suppression is in place this exact code is filtered out of results. Editing the line lifts it automatically. Removing a suppression does not create a finding - it only lets the analyzer report that code again if it still considers it a problem.</p>` : ""}
  ${body}
  <script>
    const vscode = acquireVsCodeApi();
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('button.restore');
      if (!btn) return;
      btn.disabled = true;
      document.getElementById('state-' + btn.dataset.index).textContent = 'removing…';
      vscode.postMessage({ type: 'restore', index: Number(btn.dataset.index) });
    });
    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (msg.type !== 'restored') return;
      const row = document.getElementById('row-' + msg.index);
      const state = document.getElementById('state-' + msg.index);
      // The analyzer decides whether anything is reported — removing the
      // suppression only stops this code being filtered out.
      if (state) {
        state.textContent = 'Suppression removed - the analyzer can report this again';
        state.className = 'state ok';
      }
      if (row) row.classList.add('done');
    });
  </script>
</body></html>`;
  }

  private async onMessage(msg: any): Promise<void> {
    if (msg?.type !== "restore") return;
    const item = this.forThisFile()[msg.index];
    if (!item) return;

    this.removingHere = true;
    try {
      await unsuppress(item.file, item.cwe, item.code);
    } finally {
      this.removingHere = false;
    }
    // Re-analyse straight away so the squiggle comes back now rather than on
    // the next project scan.
    await this.refresh(this.uri);
    this.panel.webview.postMessage({ type: "restored", index: msg.index });
  }

  private dispose(): void {
    DismissedPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) this.disposables.pop()?.dispose();
  }
}

const STYLES = `
* { box-sizing: border-box; }
body {
  font-family: var(--font); font-size: 13.5px; margin: 0;
  color: var(--text); background: var(--bg); padding: 22px 24px 40px; line-height: 1.55;
}
h1 { font-size: 1.3rem; font-weight: 500; margin: 0 0 4px; }
.sub { color: var(--text-dim); font-size: 0.85rem; margin: 0 0 12px; }
.note {
  font-size: 0.8rem; color: var(--text-dim);
  border-left: 2px solid var(--border-strong); padding-left: 10px; margin: 0 0 20px;
}
.empty { color: var(--text-dim); }
.row {
  border: 1px solid var(--border); border-radius: 8px; background: var(--surface);
  padding: 12px 14px; margin-bottom: 12px;
}
.row.done { opacity: 0.5; }
.head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.cwe { font-weight: 600; }
.loc, .when { color: var(--text-dim); font-size: 0.78rem; }
.when { margin-left: auto; }
pre.code {
  font-family: var(--mono); font-size: 0.78rem; background: var(--surface-2);
  padding: 8px 10px; border-radius: 4px; overflow-x: auto; margin: 8px 0 0;
  white-space: pre-wrap;
}
.actions { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
button {
  font-family: inherit; font-size: 0.8rem; padding: 4px 12px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--text); cursor: pointer;
}
button:disabled { opacity: 0.5; cursor: default; }
.state { font-size: 0.8rem; color: var(--text-dim); }
.state.ok { color: var(--good); font-weight: 600; }
`;
