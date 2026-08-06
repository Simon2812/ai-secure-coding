import * as vscode from "vscode";
import { ModelFix, ModelVulnerability } from "./client";
import { getCweInfo } from "./cweCatalog";
import { getModelResults, setModelResults, applyFixEdit, modelVulnsToDiagnostics } from "./aiFix";
import { appliedFixesFor, revertAppliedFix } from "./appliedFixes";
import { findOriginRange } from "./originMatch";
import { PALETTE } from "../report/reportHtml";
import { renderFixDiff, DIFF_STYLES } from "./diffView";
import { askAboutFinding } from "../agent/askAgent";
import { recordActivity } from "../report/history";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/** A model finding paired with the fixes that still match the current text. */
interface PanelItem {
  index: number;
  vuln: ModelVulnerability;
  fixes: ModelFix[];
}

/**
 * Shows the AI findings for one file with a diff per suggested fix.
 *
 * Complements the lightbulb quick fix rather than replacing it: the quick fix
 * is the fast path for a single finding, this is the considered one — every
 * finding in the file, each with its change shown before anything is written.
 */
export class FixPanel {
  private static current: FixPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly aiDiagnostics: vscode.DiagnosticCollection;
  private readonly output: vscode.OutputChannel;
  private readonly context: vscode.ExtensionContext;
  private uri: vscode.Uri;
  private items: PanelItem[] = [];
  /** Findings whose suggested fix no longer matches the file on disk. */
  private skipped = 0;
  private disposables: vscode.Disposable[] = [];

  private constructor(
    panel: vscode.WebviewPanel,
    uri: vscode.Uri,
    aiDiagnostics: vscode.DiagnosticCollection,
    output: vscode.OutputChannel,
    context: vscode.ExtensionContext
  ) {
    this.panel = panel;
    this.uri = uri;
    this.aiDiagnostics = aiDiagnostics;
    this.output = output;
    this.context = context;

    this.panel.webview.onDidReceiveMessage((m) => this.onMessage(m), null, this.disposables);
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  static show(
    uri: vscode.Uri,
    aiDiagnostics: vscode.DiagnosticCollection,
    output: vscode.OutputChannel,
    context: vscode.ExtensionContext
  ): void {
    if (FixPanel.current) {
      FixPanel.current.uri = uri;
      FixPanel.current.refresh();
      FixPanel.current.panel.reveal(vscode.ViewColumn.Beside, true);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "secureAssistFixes",
      "Secure Assist — AI Fixes",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      { enableScripts: true, retainContextWhenHidden: true }
    );
    FixPanel.current = new FixPanel(panel, uri, aiDiagnostics, output, context);
    FixPanel.current.refresh();
  }

  /** Re-read the file and drop fixes whose original text is no longer present. */
  private async refresh(): Promise<void> {
    const doc = await vscode.workspace.openTextDocument(this.uri);
    const code = doc.getText();

    const all = getModelResults(this.uri).map((vuln, index) => ({
      index,
      vuln,
      fixes: (vuln.fixes ?? []).filter((f) => findOriginRange(code, f.origin)),
    }));

    this.items = all.filter((item) => item.fixes.length > 0);

    // Findings the model reported a fix for that no longer matches the file —
    // usually because the code was edited since the scan. Reported rather than
    // dropped silently, so the count here matches the status bar.
    this.skipped = all.filter(
      (item) => item.fixes.length === 0 && (item.vuln.fixes ?? []).length > 0
    ).length;

    this.panel.title = `AI Fixes — ${this.uri.path.split("/").pop()}`;
    this.panel.webview.html = this.html(doc);
  }

  private html(doc: vscode.TextDocument): string {
    const fileName = vscode.workspace.asRelativePath(this.uri, false).replace(/\\/g, "/");

    const body = this.items.length
      ? this.items
          .map((item) => {
            const info = getCweInfo(item.vuln.cwe);
            const title = info ? `${item.vuln.cwe} — ${info.title}` : item.vuln.cwe;
            const line = item.vuln.start_line;

            const fixes = item.fixes
              .map((fix, fi) => {
                const id = `${item.index}-${fi}`;
                return `
                <div class="fix" id="fix-${id}">
                  ${renderFixDiff(fix)}
                  <div class="actions">
                    <button class="apply" data-id="${id}">Apply this fix</button>
                    <button class="ask" data-id="${id}">Ask about this</button>
                    <span class="state" id="state-${id}"></span>
                  </div>
                </div>`;
              })
              .join("");

            return `
            <section class="finding">
              <header>
                <span class="cwe">${escapeHtml(title)}</span>
                ${info ? `<span class="sev">${escapeHtml(info.severity)}</span>` : ""}
                ${line ? `<span class="loc" data-line="${line}">line ${line}</span>` : ""}
              </header>
              ${info ? `<p class="summary">${escapeHtml(info.summary)}</p>` : ""}
              ${info?.recommendation ? `<p class="rec">${escapeHtml(info.recommendation)}</p>` : ""}
              ${fixes}
            </section>`;
          })
          .join("")
      : `<p class="empty">No AI fixes available for this file. Run "Scan with AI" first.</p>`;

    // Fixes already written to this file. Kept visible so a change can be
    // undone here rather than through the editor's undo stack, which is lost
    // when the file closes and would leave the finding counts wrong.
    const applied = appliedFixesFor(fileName);
    const appliedBlock = applied.length
      ? `<section class="applied">
          <h2>Applied fixes</h2>
          <p class="sub">${applied.length} change${applied.length === 1 ? "" : "s"} written to this file. Reverting restores the original code and puts the finding back.</p>
          ${applied
            .map((entry, i) => {
              const info = getCweInfo(entry.cwe);
              const title = info ? `${entry.cwe} — ${info.title}` : entry.cwe;
              return `
              <div class="applied-row">
                <span class="cwe">${escapeHtml(title)}</span>
                <span class="loc" data-line="${entry.line}">line ${entry.line}</span>
                <span class="when">${new Date(entry.at).toLocaleString()}</span>
                <button class="revert" data-idx="${i}">Revert</button>
                <span class="state" id="rstate-${i}"></span>
              </div>`;
            })
            .join("")}
        </section>`
      : "";

    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><style>${PALETTE}${DIFF_STYLES}${STYLES}</style></head>
<body>
  <h1>AI suggested fixes</h1>
  <p class="sub">${escapeHtml(fileName)} · ${this.items.length} finding${this.items.length === 1 ? "" : "s"} with a suggested fix${this.skipped ? `, ${this.skipped} skipped` : ""}</p>
  ${this.skipped ? `<p class="warn">${this.skipped} suggested fix${this.skipped === 1 ? "" : "es"} could not be shown: the code it was written against is no longer in the file. Re-run "Scan with AI" to refresh them.</p>` : ""}
  <p class="warn">AI-generated fixes are not always correct. Read the change before applying it.</p>
  ${this.items.length ? `<div class="viewbar">
    <button id="v-split" class="seg active">Before / after</button><button id="v-unified" class="seg">Unified</button>
  </div>` : ""}
  ${body}
  ${appliedBlock}
  <script>
    const vscode = acquireVsCodeApi();
    document.addEventListener('click', (e) => {
      const revert = e.target.closest('button.revert');
      if (revert) {
        revert.disabled = true;
        document.getElementById('rstate-' + revert.dataset.idx).textContent = 'reverting...';
        vscode.postMessage({ type: 'revert', idx: Number(revert.dataset.idx) });
        return;
      }
      const apply = e.target.closest('button.apply');
      if (apply) {
        apply.disabled = true;
        document.getElementById('state-' + apply.dataset.id).textContent = 'applying...';
        vscode.postMessage({ type: 'apply', id: apply.dataset.id });
        return;
      }
      const ask = e.target.closest('button.ask');
      if (ask) { vscode.postMessage({ type: 'ask', id: ask.dataset.id }); return; }

      const loc = e.target.closest('.loc');
      if (loc) { vscode.postMessage({ type: 'reveal', line: Number(loc.dataset.line) }); return; }

      const seg = e.target.closest('.seg');
      if (seg) {
        const unified = seg.id === 'v-unified';
        document.body.classList.toggle('unified', unified);
        document.getElementById('v-unified').classList.toggle('active', unified);
        document.getElementById('v-split').classList.toggle('active', !unified);
      }
    });
    window.addEventListener('message', (event) => {
      const msg = event.data;
      const state = document.getElementById('state-' + msg.id);
      const card = document.getElementById('fix-' + msg.id);
      if (msg.type === 'applied') {
        if (state) { state.textContent = 'Applied'; state.className = 'state ok'; }
        if (card) card.classList.add('done');
      } else if (msg.type === 'applyFailed') {
        if (state) state.textContent = msg.message || 'Could not apply.';
        const btn = document.querySelector('button.apply[data-id="' + msg.id + '"]');
        if (btn) btn.disabled = false;
      }
    });
  </script>
</body></html>`;
  }

  /**
   * Undo an applied fix: restore the original code and put the finding back.
   *
   * Both halves matter. Restoring only the code would leave the finding
   * missing from the counts and the squiggles, so the file would look clean
   * while containing the vulnerability again.
   */
  private async revert(index: number): Promise<void> {
    const relPath = vscode.workspace.asRelativePath(this.uri, false).replace(/\\/g, "/");
    const entry = appliedFixesFor(relPath)[index];
    if (!entry) return;

    const restored = await revertAppliedFix(entry, this.uri);
    if (!restored) {
      vscode.window.showWarningMessage(
        "Secure Assist: could not revert — the code has been edited since the fix was applied."
      );
      await this.refresh();
      return;
    }

    // Put the finding back so counts, squiggles and the panel agree again.
    setModelResults(this.uri, [...getModelResults(this.uri), restored]);

    const doc = await vscode.workspace.openTextDocument(this.uri);
    this.aiDiagnostics.set(
      this.uri,
      modelVulnsToDiagnostics(doc, getModelResults(this.uri))
    );

    await recordActivity(this.context, {
      kind: "restore",
      file: relPath,
      cwe: entry.cwe,
      detail: `reverted AI fix at line ${entry.line}`,
    });

    this.output.appendLine(`[fixes] reverted ${entry.cwe} fix in ${relPath}`);
    await vscode.commands.executeCommand("secure-assist.internal.refreshStatusBar");
    await this.refresh();
  }

  private async onMessage(msg: any): Promise<void> {
    if (msg?.type === "revert") {
      await this.revert(msg.idx);
      return;
    }
    if (msg?.type === "reveal") {
      const doc = await vscode.workspace.openTextDocument(this.uri);
      const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
      const pos = new vscode.Position(Math.max(0, (msg.line ?? 1) - 1), 0);
      editor.selection = new vscode.Selection(pos, pos);
      editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
      return;
    }

    if (msg?.type === "ask") {
      const [ai, fi] = String(msg.id).split("-").map(Number);
      const target = this.items.find((it) => it.index === ai);
      if (!target) return;
      // Hand the agent the fix as well, so it can explain why the patch works.
      await askAboutFinding(
        this.uri,
        target.vuln.cwe,
        target.vuln.start_line,
        this.output,
        target.fixes[fi]
      );
      return;
    }

    if (msg?.type !== "apply") return;

    const [itemIndex, fixIndex] = String(msg.id).split("-").map(Number);
    const item = this.items.find((it) => it.index === itemIndex);
    const fix = item?.fixes[fixIndex];
    if (!fix) {
      this.panel.webview.postMessage({
        type: "applyFailed",
        id: msg.id,
        message: "This fix is no longer available.",
      });
      return;
    }

    // The diff above is the preview, so the change is written without a second
    // confirmation dialog.
    const applied = await applyFixEdit(this.uri, fix, this.aiDiagnostics, item!.vuln.cwe);
    if (applied) {
      this.output.appendLine(`[fixes] applied ${item!.vuln.cwe} fix in ${this.uri.fsPath}`);
      await recordActivity(this.context, {
        kind: "fix",
        file: vscode.workspace.asRelativePath(this.uri, false).replace(/\\/g, "/"),
        cwe: item!.vuln.cwe,
        detail: "applied from the fixes panel",
      });
      this.panel.webview.postMessage({ type: "applied", id: msg.id });
      // Re-render so the change moves into "Applied fixes" with its Revert
      // button. The message above only updates the button that was clicked.
      await this.refresh();
    } else {
      this.panel.webview.postMessage({
        type: "applyFailed",
        id: msg.id,
        message: "Could not apply — the code may have changed.",
      });
    }
  }

  private dispose(): void {
    FixPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) this.disposables.pop()?.dispose();
  }
}

const STYLES = `
* { box-sizing: border-box; }
body {
  font-family: var(--font); font-size: 13.5px; margin: 0;
  color: var(--text); background: var(--bg); padding: 22px 24px 40px; line-height: 1.5;
}
h1 { font-size: 1.3rem; font-weight: 500; margin: 0 0 4px; }
.sub { color: var(--text-dim); font-size: 0.85rem; margin: 0 0 10px; }
.warn {
  font-size: 0.8rem; color: var(--warn); border: 1px solid var(--warn);
  border-radius: 6px; padding: 7px 11px; margin: 0 0 20px; background: transparent;
}
.empty { color: var(--text-dim); }
section.applied {
  margin-top: 26px; padding-top: 14px;
  border-top: 1px solid var(--border);
}
section.applied h2 { font-size: 0.95rem; margin: 0 0 4px; }
.applied-row {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 7px 0; border-bottom: 1px solid var(--border);
  font-size: 0.82rem;
}
.applied-row .when { color: var(--text-dim); font-size: 0.74rem; }
.applied-row .revert { margin-left: auto; }
section.finding {
  border: 1px solid var(--border); border-radius: 8px;
  background: var(--surface); padding: 14px 16px; margin-bottom: 14px;
}
section.finding header { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.cwe { font-weight: 600; }
.sev {
  font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
  color: var(--text-dim); border: 1px solid var(--border-strong);
  border-radius: 999px; padding: 1px 8px;
}
.loc { font-size: 0.8rem; color: var(--text-dim); cursor: pointer; text-decoration: underline; }
.summary { margin: 8px 0 4px; }
.rec { margin: 0 0 12px; color: var(--text-dim); font-size: 0.85rem; }
.fix { margin-top: 12px; }
.fix.done { opacity: 0.55; }

/* View toggle: both diffs are in the DOM, CSS picks one. */
.viewbar { display: flex; margin: 0 0 16px; }
button.seg {
  background: var(--surface); color: var(--text-dim); border: 1px solid var(--border);
  border-radius: 0; padding: 4px 12px; font-size: 0.78rem;
}
button.seg:first-child { border-radius: 4px 0 0 4px; }
button.seg:last-child { border-radius: 0 4px 4px 0; border-left: none; }
button.seg.active { color: var(--text); background: var(--surface-2); border-color: var(--border-strong); }
.view-unified { display: none; }
body.unified .view-unified { display: block; }
body.unified .view-split { display: none; }

.actions { display: flex; align-items: center; gap: 10px; margin-top: 10px; }
button {
  font-family: inherit; font-size: 0.82rem; padding: 5px 14px; border-radius: 4px;
  border: 1px solid transparent; background: var(--accent); color: var(--accent-fg); cursor: pointer;
}
button.ask { background: var(--surface-2); color: var(--text); border-color: var(--border); }
button:disabled { opacity: 0.5; cursor: default; }
.state { font-size: 0.8rem; color: var(--text-dim); }
.state.ok { color: var(--good); font-weight: 600; }
`;
