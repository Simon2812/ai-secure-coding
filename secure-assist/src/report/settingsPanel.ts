import * as vscode from "vscode";
import * as http from "http";
import * as fs from "fs";
import * as path from "path";
import { URL } from "url";
import {
  ALL_CWES,
  enabledMap,
  setCweEnabled,
  setAllCwes,
  isLiveModeEnabled,
  setLiveMode,
} from "./settings";
import {
  listSuppressions,
  unsuppress,
  clearSuppressions,
  onDidChangeSuppressions,
  Suppression,
} from "./suppressions";
import { getCweInfo } from "../model/cweCatalog";
import { getModelEndpoint } from "../model/client";
import { clearHistory, clearActivity, loadActivity } from "./history";
import {
  clearAllModelResults,
  clearModelResults,
  filesWithModelResults,
  getModelResults,
  onDidChangeModelResults,
} from "../model/aiFix";
import { PALETTE } from "./reportHtml";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Configuration and stored-state management in one place.
 *
 * VSCode's own settings UI can edit the same values, but the panel groups them
 * with the things they affect — the suppression list, the model connection —
 * so a decision and its consequences are visible together.
 */
export class SettingsPanel {
  private static current: SettingsPanel | undefined;

  private readonly panel: vscode.WebviewPanel;
  private readonly context: vscode.ExtensionContext;
  private readonly onChanged: () => void;
  private disposables: vscode.Disposable[] = [];
  /** Set while this panel is the one changing the list, so its own rows keep
   *  their feedback and a bulk removal re-renders once rather than per item. */
  private mutatingHere = false;

  private constructor(
    panel: vscode.WebviewPanel,
    context: vscode.ExtensionContext,
    onChanged: () => void
  ) {
    this.panel = panel;
    this.context = context;
    this.onChanged = onChanged;
    this.render();
    this.panel.webview.onDidReceiveMessage((m) => this.onMessage(m), null, this.disposables);
    // A finding dismissed or restored elsewhere must show up in the suppression
    // list here without the settings screen being closed and reopened.
    onDidChangeSuppressions(
      () => {
        if (!this.mutatingHere) this.render();
      },
      null,
      this.disposables
    );
    // Same for AI findings: a scan or a clear done elsewhere changes what this
    // screen offers to remove, so the list cannot be built once and left.
    onDidChangeModelResults(
      () => {
        if (!this.mutatingHere) this.render();
      },
      null,
      this.disposables
    );
    this.panel.onDidDispose(() => this.dispose(), null, this.disposables);
  }

  static show(context: vscode.ExtensionContext, onChanged: () => void): void {
    if (SettingsPanel.current) {
      SettingsPanel.current.render();
      SettingsPanel.current.panel.reveal(vscode.ViewColumn.Active);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      "secureAssistSettings",
      "Secure Assist - Settings",
      vscode.ViewColumn.Active,
      { enableScripts: true, retainContextWhenHidden: true }
    );
    SettingsPanel.current = new SettingsPanel(panel, context, onChanged);
  }

  /** Files holding AI findings, with how many, newest scan order aside. */
  private aiFiles(): { path: string; uri: vscode.Uri; count: number }[] {
    return filesWithModelResults()
      .map((uri) => ({
        uri,
        path: vscode.workspace.asRelativePath(uri, false).replace(/\\/g, "/"),
        count: getModelResults(uri).length,
      }))
      .filter((f) => f.count > 0)
      .sort((a, b) => a.path.localeCompare(b.path));
  }

  private render(): void {
    const map = enabledMap();
    const disabledCount = ALL_CWES.filter((c) => map[c] === false).length;
    const suppressions = listSuppressions();

    const byFile = new Map<string, Suppression[]>();
    for (const s of suppressions) {
      const list = byFile.get(s.file) ?? [];
      list.push(s);
      byFile.set(s.file, list);
    }

    // Files can be deleted, renamed or moved while their suppressions remain.
    // Those entries can never match anything again, so they are marked rather
    // than silently kept — a stale list is how a user loses trust in the panel.
    const missingFiles = new Set(
      [...byFile.keys()].filter((file) => !this.fileExists(file))
    );
    const missingCount = [...missingFiles].reduce(
      (n, file) => n + (byFile.get(file)?.length ?? 0),
      0
    );

    const cweRows = ALL_CWES.map((cwe) => {
      const info = getCweInfo(cwe);
      const on = map[cwe] !== false;
      return `
      <label class="cwe-toggle ${on ? "" : "off"}">
        <input type="checkbox" data-cwe="${cwe}" ${on ? "checked" : ""} />
        <span class="cwe-id">${cwe}</span>
        <span class="cwe-title">${escapeHtml(info?.title ?? "")}</span>
        <span class="cwe-sev">${escapeHtml(info?.severity ?? "")}</span>
      </label>`;
    }).join("");

    // One collapsed group per file: the list can grow long on a real project.
    const suppressionRows = suppressions.length
      ? [...byFile.entries()]
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(
            ([file, items]) => `
        <details class="file-group${missingFiles.has(file) ? " missing" : ""}">
          <summary>
            <span class="chev">▸</span>
            <span class="fname">${escapeHtml(file)}</span>
            ${missingFiles.has(file) ? `<span class="missing-tag">file no longer exists</span>` : ""}
            <span class="count">${items.length}</span>
          </summary>
          <div class="group-body">
          ${items
            .map(
              (s) => `
            <div class="sup-row" data-file="${escapeHtml(s.file)}" data-cwe="${escapeHtml(s.cwe)}" data-code="${escapeHtml(s.code)}">
              <span class="sup-cwe">${escapeHtml(s.cwe)}</span>
              <code class="sup-code">${escapeHtml(s.code.length > 100 ? s.code.slice(0, 100) + "…" : s.code)}</code>
              <span class="sup-when">${new Date(s.at).toLocaleDateString()}</span>
              <button class="unsuppress">Remove</button>
            </div>`
            )
            .join("")}
          </div>
        </details>`
          )
          .join("")
      : `<p class="muted">Nothing is suppressed in this workspace.</p>`;

    // AI findings held for this workspace, per file. Clearing the lot is often
    // more than is wanted - usually one file's scan is stale or wrong - so each
    // file can be discarded on its own.
    const aiFiles = this.aiFiles();
    const aiTotal = aiFiles.reduce((n, f) => n + f.count, 0);
    const aiRows = aiFiles.length
      ? aiFiles
          .map(
            (f) => `
        <div class="sup-row${this.fileExists(f.path) ? "" : " missing"}" data-file="${escapeHtml(f.path)}">
          <span class="fname">${escapeHtml(f.path)}</span>
          ${this.fileExists(f.path) ? "" : `<span class="missing-tag">file no longer exists</span>`}
          <span class="count">${f.count}</span>
          <button class="clear-file-ai" data-file="${escapeHtml(f.path)}">Clear</button>
        </div>`
          )
          .join("")
      : `<p class="muted">No AI findings are stored for this workspace.</p>`;

    // Activity, also grouped per file. Project-level events (deep scans) have
    // no file of their own, so they get their own group.
    const activity = [...loadActivity(this.context)].reverse();
    const actByFile = new Map<string, typeof activity>();
    for (const e of activity) {
      const key = e.file ?? "Project-wide";
      const list = actByFile.get(key) ?? [];
      list.push(e);
      actByFile.set(key, list);
    }
    const label: Record<string, string> = {
      scan: "scan",
      fix: "fix",
      dismiss: "suppressed",
      restore: "unsuppressed",
    };
    const activityGroups = activity.length
      ? [...actByFile.entries()]
          .sort((a, b) => (a[0] === "Project-wide" ? -1 : b[0] === "Project-wide" ? 1 : a[0].localeCompare(b[0])))
          .map(
            ([file, events]) => `
        <details class="file-group">
          <summary>
            <span class="chev">▸</span>
            <span class="fname">${escapeHtml(file)}</span>
            <span class="count">${events.length}</span>
          </summary>
          <div class="group-body">
          ${events
            .map(
              (e) => `
            <div class="act-row ${e.kind}">
              <span class="act-kind">${label[e.kind] ?? e.kind}</span>
              <span class="act-detail">${escapeHtml([e.cwe, e.detail].filter(Boolean).join(" · "))}</span>
              <span class="act-when">${new Date(e.at).toLocaleString()}</span>
            </div>`
            )
            .join("")}
          </div>
        </details>`
          )
          .join("")
      : `<p class="muted">Nothing recorded yet.</p>`;

    this.panel.webview.html = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><style>${PALETTE}${STYLES}</style></head>
<body>
  <h1>Secure Assist settings</h1>
  <p class="sub">These apply to this workspace.</p>

  <section>
    <div class="sec-head">
      <h2>Reported weaknesses</h2>
      <div class="sec-actions">
        <button id="all-on" class="ghost">Enable all</button>
        <button id="all-off" class="ghost">Disable all</button>
      </div>
    </div>
    <p class="warn-box">
      Turning a weakness off does not make the code safer - it only stops the tool
      reporting it. Those findings disappear from results <em>and</em> from the project
      score, so the score will rise even though nothing changed. Disable a category
      only when it genuinely does not apply to this project.
    </p>
    <div class="cwe-grid">${cweRows}</div>
    <p class="muted" id="disabledNote">${
      disabledCount > 0
        ? `${disabledCount} of ${ALL_CWES.length} weaknesses are not being reported.`
        : ""
    }</p>
  </section>

  <section>
    <h2>Analysis</h2>
    <label class="row-toggle">
      <input type="checkbox" id="live" ${isLiveModeEnabled() ? "checked" : ""} />
      <span>Analyse as I type <span class="muted">(otherwise only on save)</span></span>
    </label>
  </section>

  <section>
    <div class="sec-head">
      <h2>Model server</h2>
      <div class="sec-actions"><button id="test" class="ghost">Test connection</button></div>
    </div>
    <div class="kv"><span>Endpoint</span><code>${escapeHtml(getModelEndpoint())}</code></div>
    <div class="status-line" id="conn"></div>
    <p class="muted">Used by "Scan with AI" and "Verify with AI". Change the endpoint in VSCode settings.</p>
  </section>

  <section>
    <div class="sec-head">
      <h2>Suppressed findings</h2>
      <div class="sec-actions">
        ${missingCount ? `<button id="prune-sup" class="ghost">Remove ${missingCount} for missing file${missingCount === 1 ? "" : "s"}</button>` : ""}
        ${suppressions.length ? `<button id="clear-sup" class="ghost danger">Remove all</button>` : ""}
      </div>
    </div>
    <p class="muted">Removing a suppression does not create a finding - it only lets the analyzer report that code again.</p>
    ${missingCount ? `<p class="warn-line">${missingCount} suppression${missingCount === 1 ? " refers" : "s refer"} to files that no longer exist. They can never match again and are safe to remove.</p>` : ""}
    <div id="sup-list">${suppressionRows}</div>
  </section>

  <section>
    <div class="sec-head">
      <h2>AI findings</h2>
      <div class="sec-actions">
        ${aiTotal ? `<button id="clear-ai" class="ghost danger">Clear all</button>` : ""}
      </div>
    </div>
    <p class="muted">Findings produced by "Scan with AI" and "Verify with AI", kept per file. Clearing them does not change your code and does not affect static analyzer findings.</p>
    <div id="ai-list">${aiRows}</div>
  </section>

  <section>
    <div class="sec-head">
      <h2>Activity</h2>
      <div class="sec-actions">
        <button id="clear-hist" class="ghost danger">Clear scan history</button>
        <button id="clear-act" class="ghost danger">Clear activity log</button>
      </div>
    </div>
    <p class="muted">Scans, fixes and suppressions recorded in this workspace. Scan history separately drives the trend line in the report.</p>
    <div id="act-list">${activityGroups}</div>
    <div class="status-line" id="dataMsg"></div>
  </section>

  <script>
    const vscode = acquireVsCodeApi();

    document.addEventListener('change', (e) => {
      const cb = e.target.closest('input[data-cwe]');
      if (cb) {
        cb.closest('.cwe-toggle').classList.toggle('off', !cb.checked);
        vscode.postMessage({ type: 'cwe', cwe: cb.dataset.cwe, enabled: cb.checked });
        return;
      }
      if (e.target.id === 'live') {
        vscode.postMessage({ type: 'live', enabled: e.target.checked });
      }
    });

    document.addEventListener('click', (e) => {
      const btn = e.target.closest('button');
      if (!btn) return;
      if (btn.id === 'all-on')      vscode.postMessage({ type: 'allCwes', enabled: true });
      else if (btn.id === 'all-off') vscode.postMessage({ type: 'allCwes', enabled: false });
      else if (btn.id === 'test') {
        document.getElementById('conn').textContent = 'checking…';
        vscode.postMessage({ type: 'test' });
      }
      else if (btn.id === 'clear-sup')  vscode.postMessage({ type: 'clearSuppressions' });
      else if (btn.id === 'prune-sup')  vscode.postMessage({ type: 'pruneSuppressions' });
      else if (btn.id === 'clear-ai')   vscode.postMessage({ type: 'clearAiFindings' });
      else if (btn.id === 'clear-hist') vscode.postMessage({ type: 'clearHistory' });
      else if (btn.id === 'clear-act')  vscode.postMessage({ type: 'clearActivity' });
      else if (btn.classList.contains('clear-file-ai')) {
        btn.disabled = true;
        vscode.postMessage({ type: 'clearFileAi', file: btn.dataset.file });
      }
      else if (btn.classList.contains('unsuppress')) {
        const row = btn.closest('.sup-row');
        btn.disabled = true;
        vscode.postMessage({
          type: 'unsuppress',
          file: row.dataset.file, cwe: row.dataset.cwe, code: row.dataset.code,
        });
        row.classList.add('gone');
      }
    });

    window.addEventListener('message', (event) => {
      const msg = event.data;
      if (msg.type === 'conn') {
        const el = document.getElementById('conn');
        el.textContent = msg.text;
        el.className = 'status-line ' + (msg.ok ? 'ok' : 'bad');
      } else if (msg.type === 'dataMsg') {
        document.getElementById('dataMsg').textContent = msg.text;
      }
    });
  </script>
</body></html>`;
  }

  private async onMessage(msg: any): Promise<void> {
    switch (msg?.type) {
      case "cwe":
        await setCweEnabled(msg.cwe, !!msg.enabled);
        this.onChanged();
        break;
      case "allCwes": {
        // Turning everything off silences the tool entirely, so it is confirmed.
        if (!msg.enabled) {
          const ok = await vscode.window.showWarningMessage(
            "Stop reporting every weakness?",
            {
              modal: true,
              detail:
                "Secure Assist will report nothing until at least one weakness is " +
                "enabled again, and every project score will read 100 regardless of " +
                "what the code contains.",
            },
            "Disable all"
          );
          if (ok !== "Disable all") return;
        }
        await setAllCwes(!!msg.enabled);
        this.onChanged();
        this.render();
        break;
      }
      case "live":
        await setLiveMode(!!msg.enabled);
        break;
      case "test":
        await this.testConnection();
        break;
      case "clearFileAi": {
        const target = this.aiFiles().find((f) => f.path === msg.file);
        if (!target) return;

        const ok = await vscode.window.showWarningMessage(
          `Discard the AI findings for ${target.path}?`,
          {
            modal: true,
            detail:
              `${target.count} finding${target.count === 1 ? "" : "s"} and any fixes suggested ` +
              "for them are removed for this file only. Other files keep theirs, and static " +
              "analyzer findings are not affected.",
          },
          "Discard"
        );
        if (ok !== "Discard") {
          this.render(); // re-enable the button the webview disabled
          return;
        }

        this.mutatingHere = true;
        try {
          clearModelResults(target.uri);
        } finally {
          this.mutatingHere = false;
        }
        await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");
        this.onChanged();
        this.render();
        this.panel.webview.postMessage({
          type: "dataMsg",
          text: `Cleared ${target.count} AI finding${target.count === 1 ? "" : "s"} for ${target.path}.`,
        });
        break;
      }
      case "unsuppress":
        this.mutatingHere = true;
        try {
          await unsuppress(msg.file, msg.cwe, msg.code);
        } finally {
          this.mutatingHere = false;
        }
        this.onChanged();
        break;
      case "clearSuppressions": {
        const ok = await vscode.window.showWarningMessage(
          "Remove every suppression in this workspace?",
          {
            modal: true,
            detail:
              "All previously dismissed findings become eligible to be reported " +
              "again. This cannot be undone - the record of what was dismissed is lost.",
          },
          "Remove all"
        );
        if (ok !== "Remove all") return;
        this.mutatingHere = true;
        try {
          await clearSuppressions();
        } finally {
          this.mutatingHere = false;
        }
        this.onChanged();
        this.render();
        break;
      }
      case "pruneSuppressions": {
        const stale = listSuppressions().filter((s) => !this.fileExists(s.file));
        if (stale.length === 0) return;
        this.mutatingHere = true;
        try {
          for (const s of stale) await unsuppress(s.file, s.cwe, s.code);
        } finally {
          this.mutatingHere = false;
        }
        this.onChanged();
        this.render();
        this.panel.webview.postMessage({
          type: "dataMsg",
          text: `Removed ${stale.length} suppression${stale.length === 1 ? "" : "s"} for files that no longer exist.`,
        });
        break;
      }
      case "clearAiFindings": {
        const ok = await vscode.window.showWarningMessage(
          "Discard every AI finding saved in this workspace?",
          {
            modal: true,
            detail:
              "Findings produced by \"Scan with AI\" and \"Verify with AI\" are " +
              "removed, along with their suggested fixes. Static analyzer findings " +
              "are not affected. Recovering them means running the AI scan again.",
          },
          "Discard"
        );
        if (ok !== "Discard") return;
        await clearAllModelResults();
        await vscode.commands.executeCommand("secure-assist.internal.refreshAiDiagnostics");
        this.panel.webview.postMessage({
          type: "dataMsg",
          text: "AI findings discarded.",
        });
        break;
      }
      case "clearHistory": {
        const ok = await vscode.window.showWarningMessage(
          "Clear the scan history for this workspace?",
          {
            modal: true,
            detail:
              "The recorded scans, their scores and the trend line are deleted. " +
              "The scan counter resets to zero. This cannot be undone.",
          },
          "Clear history"
        );
        if (ok !== "Clear history") return;
        await clearHistory(this.context);
        // The report panel keeps its own copy of the history, so clearing
        // storage alone leaves it showing a stale count until the next scan.
        await vscode.commands.executeCommand("secure-assist.internal.refreshReportHistory");
        this.panel.webview.postMessage({
          type: "dataMsg",
          text: "Scan history cleared - the trend line and scan count start fresh.",
        });
        break;
      }
      case "clearActivity":
        await clearActivity(this.context);
        this.render();
        break;
    }
  }

  /**
   * Does the file a suppression refers to still exist?
   *
   * Suppressions store a workspace-relative path. Uses a synchronous check
   * because the panel renders synchronously; the paths are few and local.
   */
  private fileExists(relPath: string): boolean {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders?.length) return true; // no workspace: cannot judge, keep it
    for (const folder of folders) {
      const full = path.join(folder.uri.fsPath, relPath);
      try {
        if (fs.existsSync(full)) return true;
      } catch {
        /* unreadable path — treat as present rather than delete blindly */
        return true;
      }
    }
    return false;
  }

  /** Ping the model server so the user knows before a scan, not during one. */
  private async testConnection(): Promise<void> {
    const endpoint = getModelEndpoint();
    const url = new URL(`${endpoint}/health`);
    const started = Date.now();

    const report = (ok: boolean, text: string) =>
      this.panel.webview.postMessage({ type: "conn", ok, text });

    const req = http.get(
      { hostname: url.hostname, port: url.port, path: url.pathname, timeout: 5000 },
      (res) => {
        res.resume();
        const ms = Date.now() - started;
        if (res.statusCode === 200) report(true, `Reachable (${ms} ms) - the model is ready.`);
        else report(false, `Responded with HTTP ${res.statusCode}.`);
      }
    );
    req.on("timeout", () => {
      req.destroy();
      report(false, "No response within 5s - the container may still be loading the model.");
    });
    req.on("error", () =>
      report(false, `Not reachable at ${endpoint} - is the Docker container running?`)
    );
  }

  private dispose(): void {
    SettingsPanel.current = undefined;
    this.panel.dispose();
    while (this.disposables.length) this.disposables.pop()?.dispose();
  }
}

const STYLES = `
* { box-sizing: border-box; }
body {
  font-family: var(--font); font-size: 13.5px; margin: 0;
  color: var(--text); background: var(--bg); padding: 24px 28px 48px; line-height: 1.55;
  max-width: 900px;
}
h1 { font-size: 1.4rem; font-weight: 500; margin: 0 0 4px; }
h2 { font-size: 0.95rem; font-weight: 500; margin: 0; }
.sub { color: var(--text-dim); font-size: 0.85rem; margin: 0 0 24px; }
.muted { color: var(--text-dim); font-size: 0.8rem; margin: 6px 0 12px; }
/* Stated where the consequence is not obvious from the control itself. */
.warn-box {
  font-size: 0.8rem; color: var(--warn); line-height: 1.5;
  border: 1px solid var(--warn); border-radius: 6px;
  padding: 9px 12px; margin: 10px 0 14px;
}
.warn-box em { font-style: normal; font-weight: 600; }
section {
  border: 1px solid var(--border); border-radius: 8px;
  background: var(--surface); padding: 16px 18px; margin-bottom: 16px;
}
.sec-head { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.sec-actions { margin-left: auto; display: flex; gap: 8px; }

button {
  font-family: inherit; font-size: 0.8rem; padding: 4px 12px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--text); cursor: pointer;
}
button.ghost { background: transparent; color: var(--text-dim); }
button.ghost:hover { color: var(--text); border-color: var(--border-strong); }
button.danger:hover { color: var(--bad); border-color: var(--bad); }
button:disabled { opacity: 0.4; cursor: default; }

.cwe-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 2px 20px; }
.cwe-toggle {
  display: flex; align-items: center; gap: 10px; padding: 6px 0; cursor: pointer;
  border-bottom: 1px solid transparent;
}
.cwe-toggle.off { opacity: 0.42; }
.cwe-id { font-weight: 600; flex: 0 0 5.5em; }
.cwe-title { flex: 1; min-width: 0; }
.cwe-sev { font-size: 0.7rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.04em; }
input[type="checkbox"] { accent-color: var(--accent); width: 15px; height: 15px; }

.row-toggle { display: flex; align-items: center; gap: 10px; cursor: pointer; margin-top: 8px; }
.kv { display: flex; gap: 12px; align-items: baseline; margin: 8px 0; }
.kv span { color: var(--text-dim); font-size: 0.8rem; flex: 0 0 5em; }
.kv code { font-family: var(--mono); font-size: 0.8rem; }
.status-line { font-size: 0.8rem; color: var(--text-dim); min-height: 1.2em; margin-top: 6px; }
.status-line.ok { color: var(--good); }
.status-line.bad { color: var(--bad); }

/* Collapsed per-file groups so long lists stay navigable. */
details.file-group {
  border: 1px solid var(--border); border-radius: 6px;
  background: var(--bg); margin-bottom: 6px;
}
details.file-group > summary {
  cursor: pointer; padding: 7px 12px; display: flex; align-items: center;
  gap: 10px; user-select: none; font-size: 0.82rem;
}
details.file-group > summary::-webkit-details-marker { display: none; }
details.file-group.missing > summary .fname { text-decoration: line-through; opacity: .65; }
.missing-tag {
  font-size: 11px; padding: 1px 6px; border-radius: 9px;
  color: var(--warn); border: 1px solid var(--warn); opacity: .85;
}
.warn-line {
  margin: 4px 0 10px; font-size: 12px; color: var(--warn);
}
details.file-group > summary:hover { background: var(--hover); }
.chev { color: var(--text-dim); transition: transform 0.12s ease; display: inline-block; }
details.file-group[open] > summary .chev { transform: rotate(90deg); }
.fname { flex: 1; min-width: 0; font-family: var(--mono); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.count {
  flex: 0 0 auto; font-size: 0.72rem; color: var(--text-dim);
  border: 1px solid var(--border); border-radius: 999px; padding: 0 8px;
}
.group-body { padding: 2px 12px 10px 24px; }

.act-row {
  display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
  padding: 4px 0 4px 10px; border-left: 2px solid var(--border); font-size: 0.8rem;
}
.act-row.fix { border-left-color: var(--good); }
.act-row.scan { border-left-color: var(--accent); }
.act-row.dismiss { border-left-color: var(--text-dim); }
.act-row.restore { border-left-color: var(--warn); }
.act-kind {
  flex: 0 0 7em; text-transform: uppercase; font-size: 0.68rem;
  letter-spacing: 0.05em; color: var(--text-dim);
}
.act-detail { flex: 1 1 200px; min-width: 0; }
.act-when { color: var(--text-dim); font-size: 0.72rem; margin-left: auto; }

.sup-row {
  display: flex; align-items: center; gap: 10px;
  padding: 5px 0 5px 10px; border-left: 2px solid var(--border); font-size: 0.8rem;
}
.sup-row.gone { opacity: 0.4; }
.sup-cwe { font-weight: 600; flex: 0 0 auto; }
.sup-code {
  flex: 1; min-width: 0; font-family: var(--mono); font-size: 0.75rem; color: var(--text-dim);
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.sup-when { color: var(--text-dim); font-size: 0.72rem; }
`;
