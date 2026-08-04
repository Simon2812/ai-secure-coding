import { ScanReport, FileReport } from "./scanner";
import { getCweInfo } from "../model/cweCatalog";
import { scoreBand, severityOf } from "./score";
import { buildTree, collapseSingleChildFolders, FolderNode } from "./tree";
import { ScanRecord, ActivityEvent, sparklineSvg } from "./history";
import { Suppression } from "./suppressions";
import { DIFF_STYLES } from "../model/diffView";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * Self-contained palette.
 *
 * The report deliberately does not inherit VSCode's theme variables: those vary
 * wildly between themes (accent-coloured panel borders, unusual surfaces) and
 * made the report look different — and often wrong — for every user. Defining
 * the colours here keeps it identical everywhere and lets the exported file
 * render the same in a browser.
 *
 * Dark is the default; light is applied from the VSCode body class or, for the
 * exported file, the reader's system preference.
 */
export const PALETTE = `
:root {
  color-scheme: light dark;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;

  --bg: #14161a;
  --surface: #1b1e24;
  --surface-2: #22262d;
  --border: #2c313a;
  --border-strong: #3b414b;
  --hover: #232830;
  --text: #e3e6ea;
  --text-dim: #98a0aa;
  --accent: #4f9ef8;
  --accent-fg: #0b1017;
  --good: #4ac26b;
  --warn: #d9a441;
  --bad: #f0665f;
  --ai: #a274f0;
}

/* Light: VSCode marks the webview body; a browser reports the OS preference. */
body.vscode-light,
body.vscode-high-contrast-light {
  --bg: #ffffff;
  --surface: #f7f8fa;
  --surface-2: #eef0f4;
  --border: #dce0e6;
  --border-strong: #c3c9d2;
  --hover: #f0f2f5;
  --text: #1c2027;
  --text-dim: #626a75;
  --accent: #2563eb;
  --accent-fg: #ffffff;
  --good: #1a7f37;
  --warn: #9a6700;
  --bad: #cf222e;
  --ai: #7c3aed;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #ffffff;
    --surface: #f7f8fa;
    --surface-2: #eef0f4;
    --border: #dce0e6;
    --border-strong: #c3c9d2;
    --hover: #f0f2f5;
    --text: #1c2027;
    --text-dim: #626a75;
    --accent: #2563eb;
    --accent-fg: #ffffff;
    --good: #1a7f37;
    --warn: #9a6700;
    --bad: #cf222e;
    --ai: #7c3aed;
  }
}
`;

const STYLES = `
* { box-sizing: border-box; }
body {
  font-family: var(--font);
  font-size: 13.5px;
  color: var(--text);
  background: var(--bg);
  padding: 24px 28px 48px;
  line-height: 1.5;
  margin: 0;
}
h1 { font-size: 1.5rem; font-weight: 500; margin: 0 0 4px; }
.sub { color: var(--text-dim); font-size: 0.85rem; margin-bottom: 24px; }
.score-row { display: flex; align-items: center; gap: 20px; margin-bottom: 8px; }
.score { font-size: 3rem; font-weight: 600; line-height: 1; }
.score.good { color: var(--good); }
.score.warning { color: var(--warn); }
.score.critical { color: var(--bad); }
.score-label { color: var(--text-dim); font-size: 0.85rem; }
.score-meta { flex: 1; }
.score-label.delta:empty { display: none; }
.trend { display: flex; align-items: center; gap: 10px; }
.trend-label { color: var(--text-dim); font-size: 0.78rem; line-height: 1.4; }
.up { color: var(--good); font-weight: 600; }
.down { color: var(--bad); font-weight: 600; }
.sparkline { display: block; }
.summary { display: flex; gap: 10px; flex-wrap: wrap; margin: 16px 0 28px; }
.pill {
  border: 1px solid var(--border);
  border-radius: 999px; padding: 4px 12px; font-size: 0.8rem;
}
.pill.critical { border-color: var(--bad); color: var(--bad); }
.pill.medium   { border-color: var(--warn); color: var(--warn); }
.pill.low      { border-color: var(--text-dim); color: var(--text-dim); }
details {
  border: 1px solid var(--border);
  border-radius: 6px; margin-bottom: 8px; background: var(--surface);
}
details[open] { padding-bottom: 6px; }
summary {
  cursor: pointer; padding: 10px 14px; display: flex;
  align-items: center; gap: 12px; user-select: none;
}
summary::-webkit-details-marker { display: none; }
summary:hover { background: var(--hover); }
.file-path { flex: 1; font-family: var(--mono); font-size: 0.85rem; }
.file-score { font-weight: 600; font-variant-numeric: tabular-nums; }
.file-score.good { color: var(--good); }
.file-score.warning { color: var(--warn); }
.file-score.critical { color: var(--bad); }
.clean { color: var(--good); font-size: 0.8rem; }
.finding {
  margin: 0 14px 10px; padding: 12px 14px;
  border-left: 3px solid var(--border);
  background: var(--bg); border-radius: 0 4px 4px 0;
}
.finding.critical { border-left-color: var(--bad); }
.finding.medium   { border-left-color: var(--warn); }
.finding.low      { border-left-color: var(--text-dim); }
/* Reported by the model but not by the static analyzer. */
.finding.ai-only { border-left-color: var(--ai); border-left-style: dashed; }
.badge-ai {
  font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
  color: var(--ai); border: 1px solid var(--ai); border-radius: 999px;
  padding: 1px 8px; white-space: nowrap;
}
.finding-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.cwe { font-weight: 600; }
.loc { color: var(--text-dim); font-size: 0.8rem; cursor: pointer; text-decoration: underline; }
.loc-static { color: var(--text-dim); font-size: 0.8rem; }
.msg { margin: 6px 0; }
.rec { color: var(--text-dim); font-size: 0.85rem; }
pre.evidence {
  font-family: var(--mono); font-size: 0.8rem;
  background: var(--surface-2); padding: 8px 10px;
  border-radius: 4px; overflow-x: auto; margin: 8px 0 0;
}
.actions { margin-top: 10px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
button {
  font-family: inherit; font-size: 0.82rem; padding: 4px 12px; border-radius: 3px;
  border: 1px solid var(--border);
  background: var(--surface-2); color: var(--text);
  cursor: pointer;
}
button.primary { background: var(--accent); color: var(--accent-fg); }
button:disabled { opacity: 0.5; cursor: default; }
/* Verification blocked because another request holds the model. */
button.verify.queued { cursor: not-allowed; opacity: 0.35; }
.status { font-size: 0.8rem; color: var(--text-dim); }
.toolbar { display: flex; gap: 8px; margin-bottom: 12px; }
.empty { color: var(--text-dim); padding: 20px 0; }

/* CWE breakdown — collapsible, one row per CWE with a proportional bar */
details.cwe-panel {
  border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface); margin-bottom: 20px;
}
details.cwe-panel > summary { font-weight: 500; }
details.cwe-panel[open] > summary .folder-icon { transform: rotate(90deg); }
.cwe-breakdown { padding: 4px 14px 12px; max-width: 720px; }
.cwe-row {
  display: flex; align-items: center; gap: 12px;
  padding: 5px 0 5px 10px; border-left: 3px solid var(--border);
  font-size: 0.85rem;
}
.cwe-row.critical { border-left-color: var(--bad); }
.cwe-row.medium   { border-left-color: var(--warn); }
.cwe-row.low      { border-left-color: var(--text-dim); }
.cwe-label { flex: 1; min-width: 0; }
.cwe-bar {
  flex: 0 0 120px; height: 6px; border-radius: 3px;
  background: var(--border); overflow: hidden;
}
.cwe-bar > span { display: block; height: 100%; background: currentColor; opacity: 0.75; }
.cwe-row.critical .cwe-bar > span { background: var(--bad); }
.cwe-row.medium   .cwe-bar > span { background: var(--warn); }
.cwe-row.low      .cwe-bar > span { background: var(--text-dim); }
.cwe-count {
  flex: 0 0 2.5em; text-align: right;
  font-variant-numeric: tabular-nums; font-weight: 600;
}

/* Collapsible side panels: activity log and dismissed findings */
details.side-panel {
  border: 1px solid var(--border); border-radius: 6px;
  background: var(--surface); margin-bottom: 12px;
}
details.side-panel > summary { font-weight: 500; }
details.side-panel[open] > summary .folder-icon { transform: rotate(90deg); }
.side-body { padding: 4px 14px 12px; }

.fp-file {
  font-family: var(--mono); font-size: 0.78rem; color: var(--text-dim);
  margin: 10px 0 4px;
}
.fp-row {
  display: flex; align-items: center; gap: 10px; flex-wrap: wrap;
  padding: 5px 0 5px 10px; border-left: 2px solid var(--border);
  font-size: 0.8rem;
}
.fp-row.restored { opacity: 0.5; }
.fp-cwe { font-weight: 600; flex: 0 0 auto; }
.fp-code {
  flex: 1; min-width: 0; font-family: var(--mono); font-size: 0.75rem;
  color: var(--text-dim); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.fp-when { color: var(--text-dim); font-size: 0.72rem; }
button.restore { font-size: 0.74rem; padding: 2px 10px; }
.fp-note { color: var(--text-dim); font-size: 0.76rem; margin: 12px 0 0; }

.act-row {
  display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap;
  padding: 4px 0 4px 10px; border-left: 2px solid var(--border); font-size: 0.8rem;
}
.act-row.fix { border-left-color: var(--good); }
.act-row.dismiss { border-left-color: var(--text-dim); }
.act-row.restore { border-left-color: var(--warn); }
.act-row.scan { border-left-color: var(--accent); }
.act-icon { flex: 0 0 1em; text-align: center; color: var(--text-dim); }
.act-kind {
  flex: 0 0 7em; text-transform: uppercase; font-size: 0.68rem;
  letter-spacing: 0.05em; color: var(--text-dim);
}
.act-what { flex: 1 1 240px; min-width: 0; }
.act-detail { color: var(--text-dim); font-size: 0.76rem; }
.act-when { color: var(--text-dim); font-size: 0.72rem; margin-left: auto; }

/* Filter bar */
.filters {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  padding: 10px 0 14px; margin-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.filters input[type="search"], .filters select {
  font-family: inherit; font-size: 0.82rem; padding: 4px 8px; border-radius: 3px;
  border: 1px solid var(--border);
  background: var(--surface); color: var(--text);
}
.filters input[type="search"] { min-width: 240px; flex: 1; }
.filters .chk { font-size: 0.82rem; display: flex; align-items: center; gap: 5px; cursor: pointer; }
.filters .spacer { flex: 1; }

/* Folder tree */
details.folder { background: transparent; border-color: var(--border); }
details.folder > summary { font-weight: 500; }
.folder-icon { display: inline-block; transition: transform 0.12s ease; color: var(--text-dim); }
details.folder[open] > summary .folder-icon { transform: rotate(90deg); }
.folder-name { flex: 1; }
.folder-body { padding: 0 10px 6px 22px; }
details.file { background: var(--surface); }

/* Per-file toolbar */
.file-tools {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  margin: 8px 14px 12px; padding-top: 10px;
  border-top: 1px solid var(--border);
}
/* Inline fix preview — replaces the old modal dialog. */
.fix-preview {
  margin: 10px 0 4px; padding: 12px; border-radius: 6px;
  border: 1px solid var(--border-strong); background: var(--surface);
}
.preview-actions { display: flex; align-items: center; gap: 10px; margin-top: 10px; flex-wrap: wrap; }

.verdict { font-size: 0.75rem; padding: 1px 8px; border-radius: 999px; border: 1px solid; }
.verdict.ok { color: var(--good); border-color: var(--good); }
.verdict.applied { color: var(--good); border-color: var(--good); background: rgba(63, 185, 80, 0.12); }
.verdict:empty { display: none; }
/* A finding whose fix has been applied stays visible but reads as resolved. */
.finding.fixed { opacity: 0.6; border-left-color: var(--good) !important; }
.finding.fixed .cwe { text-decoration: line-through; }
/* Dismissed as a false positive — kept visible so the decision is auditable. */
.finding.dismissed { opacity: 0.45; border-left-style: dotted; }
.finding.dismissed .cwe { text-decoration: line-through; }
button.dismiss { font-size: 0.76rem; }
.ai-findings:empty { display: none; }

/* Inline source viewer */
button.see-code { font-size: 0.78rem; }
.code-block {
  margin: 0 14px 12px; border: 1px solid var(--border); border-radius: 4px;
  background: var(--surface-2); overflow-x: auto;
  font-family: var(--mono); font-size: 0.78rem; line-height: 1.5;
  max-height: 460px; overflow-y: auto;
}
.code-line { display: flex; white-space: pre; border-left: 3px solid transparent; }
/* Static analyzer finding. */
.code-line.flagged { background: rgba(240, 102, 95, 0.14); border-left-color: var(--bad); }
/* Model finding — its own colour so the two sources stay distinguishable. */
.code-line.ai-flagged { background: rgba(162, 116, 240, 0.16); border-left-color: var(--ai); }
/* Flagged by both: red bar, blended tint. */
.code-line.flagged.ai-flagged {
  background: rgba(200, 110, 165, 0.16);
  border-left-color: var(--bad);
  box-shadow: inset -3px 0 0 var(--ai);
}
.code-legend {
  display: flex; gap: 14px; flex-wrap: wrap;
  margin: 0 14px 6px; font-size: 0.72rem; color: var(--text-dim);
}
.code-legend span { display: flex; align-items: center; gap: 5px; }
.code-legend i { width: 10px; height: 10px; border-radius: 2px; display: inline-block; }
.code-legend i.s { background: var(--bad); }
.code-legend i.a { background: var(--ai); }
.ln {
  flex: 0 0 3.2em; text-align: right; padding: 0 10px 0 6px;
  color: var(--text-dim); user-select: none;
}
.lc { flex: 1; padding-right: 12px; }
`;

function renderFinding(
  file: FileReport,
  index: number,
  fileIndex: number,
  interactive: boolean
): string {
  const f = file.findings[index];
  const info = getCweInfo(f.cweId);
  const sev = severityOf(f.cweId);
  const title = info ? `${f.cweId} — ${info.title}` : f.cweId;
  const id = `${fileIndex}-${index}`;

  // The exported file is a read-only artifact: jump-to-line needs the extension,
  // so it degrades to plain text there.
  const location = interactive
    ? `<span class="loc" data-file="${escapeHtml(file.path)}" data-line="${f.line}">line ${f.line}</span>`
    : `<span class="loc-static">line ${f.line}</span>`;

  return `
  <div class="finding ${sev}" data-finding-id="${id}">
    <div class="finding-head">
      <span class="cwe">${escapeHtml(title)}</span>
      ${location}
      <span class="verdict" id="verdict-${id}"></span>
    </div>
    <div class="msg">${escapeHtml(f.message)}</div>
    ${info?.recommendation ? `<div class="rec">${escapeHtml(info.recommendation)}</div>` : ""}
    ${f.evidence ? `<pre class="evidence">${escapeHtml(f.evidence)}</pre>` : ""}
    <div class="actions" id="actions-${id}">
      ${interactive
        ? `<button class="dismiss" data-file="${escapeHtml(file.path)}" data-cwe="${escapeHtml(f.cweId)}" data-line="${f.line}" title="Never report this exact code again">Not a vulnerability</button>`
        : ""}
    </div>
  </div>`;
}

/**
 * Per-file toolbar: one AI verification for the whole file (a single inference
 * covers every finding in it) plus the source viewer.
 */
function renderFileTools(file: FileReport, fileIndex: number, interactive: boolean): string {
  const verify = interactive
    ? `<button class="verify" data-file="${escapeHtml(file.path)}" data-index="${fileIndex}">Verify with AI</button>
       <span class="status" id="filestatus-${fileIndex}"></span>`
    : "";

  const code = file.code
    ? `<button class="see-code" data-target="code-${fileIndex}">See code</button>`
    : "";

  if (!verify && !code) return "";
  return `<div class="file-tools">${code}${verify}</div>`;
}

/**
 * Source lines with line numbers, flagged lines highlighted.
 * Exported so the panel can re-render a file's code after a fix is applied.
 */
export function renderCodeRows(
  code: string,
  flaggedLines: Iterable<number>,
  aiLines: Iterable<number> = []
): string {
  const flagged = new Set(flaggedLines);
  const ai = new Set(aiLines);
  return code
    .split("\n")
    .map((line, i) => {
      const n = i + 1;
      // A line both tools flagged keeps the static (red) marker and adds the
      // AI one, so agreement is visible rather than one colour hiding the other.
      const cls = [
        "code-line",
        flagged.has(n) ? "flagged" : "",
        ai.has(n) ? "ai-flagged" : "",
      ]
        .filter(Boolean)
        .join(" ");
      return `<div class="${cls}"><span class="ln">${n}</span><span class="lc">${escapeHtml(line) || "&nbsp;"}</span></div>`;
    })
    .join("");
}

/** The file's source with line numbers, vulnerable lines marked. */
function renderCode(file: FileReport, fileIndex: number): string {
  if (!file.code) return "";
  const rows = renderCodeRows(file.code, file.findings.map((f) => f.line));
  return `<div class="code-block" id="code-${fileIndex}" hidden>${rows}</div>`;
}

function renderFile(file: FileReport, fileIndex: number, interactive: boolean): string {
  const band = scoreBand(file.score);
  const count = file.findings.length;
  const header = `
    <summary>
      <span class="file-path">${escapeHtml(file.displayName ?? file.path)}</span>
      ${count === 0 ? '<span class="clean">✓ clean</span>' : `<span class="status">${count} finding${count === 1 ? "" : "s"}</span>`}
      <span class="file-score ${band}">${file.score}</span>
    </summary>`;

  const findings = file.findings
    .map((_f, i) => renderFinding(file, i, fileIndex, interactive))
    .join("");

  // Data attributes drive client-side filtering without another scan.
  const cwes = [...new Set(file.findings.map((f) => f.cweId))].join(" ");
  const sevs = [...new Set(file.findings.map((f) => severityOf(f.cweId)))].join(" ");

  // Clean files get the same tools: the model may still find something the
  // static analyzer missed, which is exactly where it adds value.
  return `<details class="file" data-path="${escapeHtml(file.path.toLowerCase())}"
      data-cwes="${escapeHtml(cwes)}" data-sevs="${escapeHtml(sevs)}"
      data-count="${count}">
    ${header}
    ${findings}
    <div class="ai-findings" id="aifindings-${fileIndex}"></div>
    ${renderFileTools(file, fileIndex, interactive)}
    ${renderCode(file, fileIndex)}
  </details>`;
}

/** Recursively render a folder and everything beneath it. */
function renderFolder(
  folder: FolderNode,
  interactive: boolean,
  counter: { next: number },
  depth = 0
): string {
  const children =
    folder.folders.map((f) => renderFolder(f, interactive, counter, depth + 1)).join("") +
    folder.files.map((f) => renderFile(f, counter.next++, interactive)).join("");

  // The synthetic root has no header of its own.
  if (folder.path === "" && depth === 0) return children;

  const band = scoreBand(folder.score);
  return `
    <details class="folder" ${depth === 0 ? "open" : ""}>
      <summary>
        <span class="folder-icon">▸</span>
        <span class="folder-name">${escapeHtml(folder.name)}</span>
        <span class="status">${folder.fileCount} file${folder.fileCount === 1 ? "" : "s"}${
          folder.findingCount > 0 ? ` · ${folder.findingCount} finding${folder.findingCount === 1 ? "" : "s"}` : ""
        }</span>
        <span class="file-score ${band}">${folder.score}</span>
      </summary>
      <div class="folder-body">${children}</div>
    </details>`;
}

/**
 * Build the report page.
 *
 * `interactive` controls whether the Verify/Fix buttons and the VSCode message
 * bridge are included — the exported HTML file is a static, read-only copy.
 */
export function buildReportHtml(
  report: ScanReport,
  interactive: boolean,
  history: ScanRecord[] = [],
  extras: { activity?: ActivityEvent[]; suppressions?: Suppression[] } = {}
): string {
  const band = scoreBand(report.score);

  const body = report.files.length === 0
    ? `<p class="empty">No source files found to scan.</p>`
    : renderFolder(
        collapseSingleChildFolders(buildTree(report.files)),
        interactive,
        { next: 0 }
      );

  const script = interactive
    ? `<script>
        const vscode = acquireVsCodeApi();
        // Elapsed-time tickers per file, cleared when the response arrives.
        const timers = {};
        // The model serves one request at a time on a single GPU, so only one
        // verification may be in flight; the rest are visibly disabled.
        let busy = false;
        // Score when this report was rendered, for the session's before/after.
        const initialProjectScore = ${report.score};
        const band = (s) => (s >= 80 ? 'good' : s >= 50 ? 'warning' : 'critical');

        function setVerifyBusy(state, activeIndex) {
          busy = state;
          document.querySelectorAll('button.verify').forEach(btn => {
            const isActive = btn.dataset.index === activeIndex;
            btn.disabled = state;
            if (state && !isActive) {
              btn.title = 'Waiting for the current AI analysis to finish';
              btn.classList.add('queued');
            } else {
              btn.title = '';
              btn.classList.remove('queued');
            }
          });
        }

        document.addEventListener('click', (e) => {
          const loc = e.target.closest('.loc');
          if (loc) {
            vscode.postMessage({ type: 'open', file: loc.dataset.file, line: Number(loc.dataset.line) });
            return;
          }
          const verify = e.target.closest('button.verify');
          if (verify) {
            if (busy) return;
            const idx = verify.dataset.index;
            // One GPU, one inference: block every other verify until this one
            // returns, so requests can't pile up and compete for VRAM.
            setVerifyBusy(true, idx);
            const status = document.getElementById('filestatus-' + idx);
            // Inference takes tens of seconds, so tick the elapsed time to make
            // it obvious the request is still in flight rather than stuck.
            let seconds = 0;
            status.textContent = 'asking the model... 0s';
            timers[idx] = setInterval(() => {
              seconds += 1;
              status.textContent = 'asking the model... ' + seconds + 's';
            }, 1000);
            vscode.postMessage({ type: 'verifyFile', index: idx, file: verify.dataset.file });
            return;
          }
          // Ask for the diff first; applying happens from the preview below.
          const fix = e.target.closest('button.fix');
          if (fix) {
            vscode.postMessage({ type: 'previewFix', id: fix.dataset.id, fixIndex: Number(fix.dataset.fixIndex) });
            return;
          }
          const confirm = e.target.closest('button.confirm-fix');
          if (confirm) {
            confirm.disabled = true;
            vscode.postMessage({ type: 'fix', id: confirm.dataset.id, fixIndex: Number(confirm.dataset.fixIndex) });
            return;
          }
          const cancel = e.target.closest('button.cancel-fix');
          if (cancel) {
            const box = document.getElementById('preview-' + cancel.dataset.id);
            if (box) box.remove();
            return;
          }
          const restore = e.target.closest('button.restore');
          if (restore) {
            const row = restore.closest('.fp-row');
            restore.disabled = true;
            vscode.postMessage({
              type: 'restore',
              file: row.dataset.file,
              cwe: row.dataset.cwe,
              code: row.dataset.code,
            });
            row.classList.add('restored');
            restore.textContent = 'Suppression removed';
            return;
          }
          const dismiss = e.target.closest('button.dismiss');
          if (dismiss) {
            // Optimistic, but reverted if the confirmation is declined.
            dismiss.disabled = true;
            dismiss.dataset.pending = dismiss.dataset.file + ':' + dismiss.dataset.line;
            vscode.postMessage({
              type: 'dismiss',
              file: dismiss.dataset.file,
              cwe: dismiss.dataset.cwe,
              line: Number(dismiss.dataset.line),
            });
            const row = dismiss.closest('.finding');
            if (row) { row.classList.add('dismissed'); }
            return;
          }
          // Toolbar actions are delegated too, so they work regardless of when
          // the script runs relative to the buttons being parsed.
          if (e.target.closest('#export')) {
            vscode.postMessage({ type: 'export' });
            return;
          }
          if (e.target.closest('#rescan')) {
            vscode.postMessage({ type: 'rescan' });
          }
        });

        function addFixButtons(container, id, count) {
          for (let i = 0; i < count; i++) {
            const b = document.createElement('button');
            b.className = 'fix primary';
            b.textContent = 'Apply fix' + (count > 1 ? ' #' + (i + 1) : '');
            b.dataset.id = id; b.dataset.fixIndex = String(i);
            container.appendChild(b);
          }
        }

        window.addEventListener('message', (event) => {
          const msg = event.data;
          const status = document.getElementById('filestatus-' + msg.index);
          if (timers[msg.index]) { clearInterval(timers[msg.index]); delete timers[msg.index]; }
          // Any reply to a verification frees the model for the next request.
          if (msg.type === 'fileVerified' || msg.type === 'verifyFailed') setVerifyBusy(false);

          if (msg.type === 'fileVerified') {
            // Only confirmations are reported: the analyzer and the model catch
            // different things, so "the AI didn't flag it" says nothing about
            // whether a static finding is real.
            const confirmed = (msg.results || []).length;
            const found = (msg.aiOnly || []).length;
            const parts = [];
            if (confirmed > 0) parts.push('AI confirmed ' + confirmed + ' finding' + (confirmed === 1 ? '' : 's'));
            if (found > 0) parts.push('found ' + found + ' the analyzer missed');
            if (status) {
              status.textContent = parts.length > 0
                ? parts.join(', ') + '.'
                : 'AI reported nothing additional for this file.';
            }

            // Confirmed findings get a badge and, where offered, their fixes.
            (msg.results || []).forEach((r) => {
              const verdict = document.getElementById('verdict-' + r.id);
              if (verdict) {
                // The model sometimes reports the same flaw at the line that
                // creates it rather than the line that uses it — say so.
                verdict.textContent = r.atLine
                  ? 'AI confirmed (at line ' + r.atLine + ')'
                  : 'AI confirmed';
                verdict.className = 'verdict ok';
              }
              const actions = document.getElementById('actions-' + r.id);
              if (actions && r.fixCount > 0) addFixButtons(actions, r.id, r.fixCount);
            });

            // Repaint the source so the model's lines show in their own colour,
            // and explain the two colours now that both are present.
            if (msg.codeRows) {
              const block = document.getElementById('code-' + msg.index);
              if (block) block.innerHTML = msg.codeRows;
              const tools = document.querySelector('#code-' + msg.index).previousElementSibling;
              if (msg.aiLineCount > 0 && tools && !document.getElementById('legend-' + msg.index)) {
                const legend = document.createElement('div');
                legend.className = 'code-legend';
                legend.id = 'legend-' + msg.index;
                legend.innerHTML =
                  '<span><i class="s"></i>static analyzer</span>' +
                  '<span><i class="a"></i>AI</span>';
                tools.insertAdjacentElement('afterend', legend);
              }
            }

            // Findings only the model reported.
            const host = document.getElementById('aifindings-' + msg.index);
            (msg.aiOnly || []).forEach((v) => {
              if (!host) return;
              const div = document.createElement('div');
              div.className = 'finding ai-only';
              div.setAttribute('data-finding-id', v.id);
              div.innerHTML =
                '<div class="finding-head">' +
                  '<span class="badge-ai">Detected by AI</span>' +
                  '<span class="cwe"></span>' +
                  '<span class="loc-static"></span>' +
                  '<span class="verdict"></span>' +
                '</div>' +
                '<div class="msg">The static analyzer did not report this issue.</div>' +
                '<div class="actions"></div>';
              div.querySelector('.cwe').textContent = v.title ? v.cwe + ' - ' + v.title : v.cwe;
              div.querySelector('.loc-static').textContent = v.line ? 'line ' + v.line : '';
              addFixButtons(div.querySelector('.actions'), v.id, v.fixCount);
              host.appendChild(div);
            });
          } else if (msg.type === 'fixPreview') {
            // Insert the diff under the finding, with its own confirm/cancel.
            const actions = document.getElementById('actions-' + msg.id);
            if (!actions) return;
            const existing = document.getElementById('preview-' + msg.id);
            if (existing) existing.remove();
            const box = document.createElement('div');
            box.className = 'fix-preview';
            box.id = 'preview-' + msg.id;
            box.innerHTML =
              msg.diffHtml +
              '<div class="preview-actions">' +
                '<button class="confirm-fix primary" data-id="' + msg.id + '" data-fix-index="' + msg.fixIndex + '">Apply</button>' +
                '<button class="cancel-fix" data-id="' + msg.id + '">Cancel</button>' +
                '<span class="status">AI fixes are not always correct — review the change.</span>' +
              '</div>';
            actions.insertAdjacentElement('afterend', box);
          } else if (msg.type === 'fixApplied') {
            const box = document.getElementById('preview-' + msg.id);
            if (box) box.remove();
            // Mark the finding as resolved and refresh the file's code + score
            // so the report reflects the edit instead of the original scan.
            const row = document.querySelector('[data-finding-id="' + msg.id + '"]');
            if (row) {
              row.classList.add('fixed');
              const verdict = row.querySelector('.verdict');
              if (verdict) { verdict.textContent = 'Fix applied'; verdict.className = 'verdict applied'; }
              const acts = row.querySelector('.actions');
              if (acts) acts.innerHTML = '';
            }

            const block = document.getElementById('code-' + msg.fileIndex);
            if (block && msg.codeRows) {
              block.innerHTML = msg.codeRows;
              // Reveal the updated code so the change is visible immediately.
              block.removeAttribute('hidden');
              const toggle = document.querySelector('button.see-code[data-target="code-' + msg.fileIndex + '"]');
              if (toggle) toggle.textContent = 'Hide code';
            }

            const fileStatus = document.getElementById('filestatus-' + msg.fileIndex);
            if (fileStatus) {
              fileStatus.textContent = 'Fix applied. ' + msg.findingCount +
                ' finding' + (msg.findingCount === 1 ? '' : 's') + ' remaining.';
            }

            const summary = block ? block.closest('details.file')?.querySelector('summary') : null;
            const scoreEl = summary ? summary.querySelector('.file-score') : null;
            if (scoreEl) {
              scoreEl.textContent = msg.score;
              scoreEl.className = 'file-score ' + band(msg.score);
            }

            // Project score moves as findings are resolved, so show where this
            // session started alongside where it is now.
            if (typeof msg.projectScore === 'number') {
              const proj = document.getElementById('projectScore');
              if (proj) {
                proj.textContent = msg.projectScore;
                proj.className = 'score ' + band(msg.projectScore);
              }
              const delta = document.getElementById('sessionDelta');
              if (delta && msg.projectScore !== initialProjectScore) {
                const diff = msg.projectScore - initialProjectScore;
                delta.innerHTML = 'this session: ' + initialProjectScore + ' → ' +
                  '<span class="' + (diff > 0 ? 'up' : 'down') + '">' + msg.projectScore +
                  ' (' + (diff > 0 ? '+' : '') + diff + ')</span>';
              }
              const clean = document.getElementById('cleanLabel');
              if (clean && typeof msg.cleanCount === 'number' && typeof msg.scannedCount === 'number') {
                clean.textContent = msg.cleanCount + ' of ' + msg.scannedCount + ' files clean';
              }
            }
          } else if (msg.type === 'dismissCancelled') {
            const btn = document.querySelector('button.dismiss[data-pending="' + msg.id + '"]');
            if (btn) {
              btn.disabled = false;
              delete btn.dataset.pending;
              const row = btn.closest('.finding');
              if (row) row.classList.remove('dismissed');
            }
          } else if (msg.type === 'dismissed') {
            // Scores move as soon as a finding is dismissed, no re-scan needed.
            const proj = document.getElementById('projectScore');
            if (proj) { proj.textContent = msg.projectScore; proj.className = 'score ' + band(msg.projectScore); }
            const clean = document.getElementById('cleanLabel');
            if (clean) clean.textContent = msg.cleanCount + ' of ' + msg.scannedCount + ' files clean';
            document.querySelectorAll('details.file').forEach(f => {
              if (f.dataset.path !== (msg.file || '').toLowerCase()) return;
              const el = f.querySelector('summary .file-score');
              if (el) { el.textContent = msg.score; el.className = 'file-score ' + band(msg.score); }
            });
          } else if (msg.type === 'verifyFailed') {
            if (status) status.textContent = msg.message || 'AI verification failed.';
          }
        });
      </script>`
    : "";

  // Which CWEs actually occur, so the breakdown and the filter only offer
  // options that will match something.
  // Trend across previous scans of this workspace. The current scan is already
  // the last entry in `history`, so the one before it is the comparison point.
  const previous = history.length >= 2 ? history[history.length - 2] : undefined;
  const change = previous ? report.score - previous.score : 0;
  const trend = history.length >= 2
    ? `<div class="trend">
        ${sparklineSvg(history.map((h) => h.score))}
        <div class="trend-label">
          ${change === 0
            ? "no change since last scan"
            : `<span class="${change > 0 ? "up" : "down"}">${change > 0 ? "▲" : "▼"} ${Math.abs(change)}</span> since last scan`}
          <br />${history.length} scans recorded
        </div>
      </div>`
    : "";

  const maxCweCount = report.byCwe.reduce((max, e) => Math.max(max, e.count), 0);
  const cweBreakdown = report.byCwe.length
    ? `<details class="cwe-panel">
        <summary>
          <span class="folder-icon">▸</span>
          <span class="folder-name">Findings by CWE</span>
          <span class="status">${report.byCwe.length} type${report.byCwe.length === 1 ? "" : "s"}</span>
        </summary>
        <div class="cwe-breakdown">
          ${report.byCwe
            .map((entry) => {
              const info = getCweInfo(entry.cwe);
              const label = info ? `${entry.cwe} — ${info.title}` : entry.cwe;
              const width = maxCweCount ? Math.round((entry.count / maxCweCount) * 100) : 0;
              return `<div class="cwe-row ${severityOf(entry.cwe)}">
                <span class="cwe-label">${escapeHtml(label)}</span>
                <span class="cwe-bar"><span style="width:${width}%"></span></span>
                <span class="cwe-count">${entry.count}</span>
              </div>`;
            })
            .join("")}
        </div>
      </details>`
    : "";

  // Dismissed findings, grouped by file, each restorable.
  const suppressions = extras.suppressions ?? [];
  const byFile = new Map<string, Suppression[]>();
  for (const s of suppressions) {
    const list = byFile.get(s.file) ?? [];
    list.push(s);
    byFile.set(s.file, list);
  }

  const dismissedPanel = suppressions.length
    ? `<details class="side-panel">
        <summary>
          <span class="folder-icon">▸</span>
          <span class="folder-name">Dismissed as false positive</span>
          <span class="status">${suppressions.length}</span>
        </summary>
        <div class="side-body">
          ${[...byFile.entries()]
            .map(
              ([file, items]) => `
            <div class="fp-file">${escapeHtml(file)}</div>
            ${items
              .map(
                (s) => `
              <div class="fp-row" data-file="${escapeHtml(s.file)}" data-cwe="${escapeHtml(s.cwe)}" data-code="${escapeHtml(s.code)}">
                <span class="fp-cwe">${escapeHtml(s.cwe)}</span>
                <code class="fp-code">${escapeHtml(s.code.length > 90 ? s.code.slice(0, 90) + "…" : s.code)}</code>
                <span class="fp-when">${new Date(s.at).toLocaleDateString()}</span>
                ${interactive ? `<button class="restore">Remove suppression</button>` : ""}
              </div>`
              )
              .join("")}`
            )
            .join("")}
          ${interactive
            ? `<p class="fp-note">Removing a suppression does not create a finding. It only stops this code being filtered out, so the analyzer can report it again on the next scan if it still considers it a problem.</p>`
            : ""}
        </div>
      </details>`
    : "";

  // What has been done to this project, newest first.
  const activity = [...(extras.activity ?? [])].reverse();
  const activityIcon: Record<ActivityEvent["kind"], string> = {
    scan: "◆",
    fix: "✓",
    dismiss: "✕",
    restore: "↺",
  };
  // The stored kind is kept as-is so older entries still resolve; only the
  // label shown to the reader is reworded.
  const activityLabel: Record<ActivityEvent["kind"], string> = {
    scan: "scan",
    fix: "fix",
    dismiss: "suppressed",
    restore: "unsuppressed",
  };
  const activityPanel = activity.length
    ? `<details class="side-panel">
        <summary>
          <span class="folder-icon">▸</span>
          <span class="folder-name">Activity</span>
          <span class="status">${activity.length} event${activity.length === 1 ? "" : "s"}</span>
        </summary>
        <div class="side-body">
          ${activity
            .map(
              (e) => `
            <div class="act-row ${e.kind}">
              <span class="act-icon">${activityIcon[e.kind] ?? "•"}</span>
              <span class="act-kind">${activityLabel[e.kind] ?? e.kind}</span>
              <span class="act-what">${escapeHtml(
                [e.cwe, e.file].filter(Boolean).join(" in ") || "project"
              )}</span>
              <span class="act-detail">${escapeHtml(e.detail ?? "")}</span>
              <span class="act-when">${new Date(e.at).toLocaleString()}</span>
            </div>`
            )
            .join("")}
        </div>
      </details>`
    : "";

  const filterBar = `
    <div class="filters">
      <input id="q" type="search" placeholder="Filter by file name or CWE..." />
      <select id="sev">
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select id="cwe">
        <option value="">All CWEs</option>
        ${report.byCwe.map((e) => `<option value="${escapeHtml(e.cwe)}">${escapeHtml(e.cwe)}</option>`).join("")}
      </select>
      <label class="chk"><input id="onlyIssues" type="checkbox" /> Only files with findings</label>
      <span class="spacer"></span>
      <button id="expandAll">Expand all</button>
      <button id="collapseAll">Collapse all</button>
      <span class="status" id="filterCount"></span>
    </div>`;

  const toolbar = interactive
    ? `<div class="toolbar">
         <button id="rescan">Re-scan project</button>
         <button id="export">Export to HTML</button>
       </div>`
    : "";

  // Source viewer, filtering and expand/collapse are pure DOM work, so they
  // ship in the exported file as well.
  const codeToggleScript = `<script>
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('button.see-code');
      if (btn) {
        const block = document.getElementById(btn.dataset.target);
        if (!block) return;
        const showing = !block.hasAttribute('hidden');
        if (showing) { block.setAttribute('hidden', ''); btn.textContent = 'See code'; }
        else { block.removeAttribute('hidden'); btn.textContent = 'Hide code'; }
        return;
      }
      if (e.target.closest('#expandAll') || e.target.closest('#collapseAll')) {
        const open = !!e.target.closest('#expandAll');
        document.querySelectorAll('details.folder, details.file').forEach(d => {
          if (open) d.setAttribute('open', ''); else d.removeAttribute('open');
        });
      }
    });

    const q = document.getElementById('q');
    const sevSel = document.getElementById('sev');
    const cweSel = document.getElementById('cwe');
    const onlyIssues = document.getElementById('onlyIssues');
    const filterCount = document.getElementById('filterCount');

    function applyFilters() {
      const text = (q.value || '').trim().toLowerCase();
      const sev = sevSel.value;
      const cwe = cweSel.value;
      const issuesOnly = onlyIssues.checked;
      let shown = 0;

      document.querySelectorAll('details.file').forEach(file => {
        const path = file.dataset.path || '';
        const cwes = file.dataset.cwes || '';
        const sevs = file.dataset.sevs || '';
        const count = Number(file.dataset.count || 0);

        // Text matches either the path or any CWE id on the file.
        const matchesText = !text || path.includes(text) || cwes.toLowerCase().includes(text);
        const matchesSev = !sev || sevs.split(' ').includes(sev);
        const matchesCwe = !cwe || cwes.split(' ').includes(cwe);
        const matchesIssues = !issuesOnly || count > 0;
        const visible = matchesText && matchesSev && matchesCwe && matchesIssues;

        file.style.display = visible ? '' : 'none';
        if (visible) shown++;
      });

      // Hide folders that no longer contain a visible file.
      document.querySelectorAll('details.folder').forEach(folder => {
        const any = folder.querySelector('details.file:not([style*="display: none"])');
        folder.style.display = any ? '' : 'none';
        if (any && (text || sev || cwe)) folder.setAttribute('open', '');
      });

      const filtering = text || sev || cwe || issuesOnly;
      filterCount.textContent = filtering ? shown + ' file' + (shown === 1 ? '' : 's') + ' shown' : '';
    }

    [q, sevSel, cweSel, onlyIssues].forEach(el => {
      el.addEventListener('input', applyFilters);
      el.addEventListener('change', applyFilters);
    });
  </script>`;

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Secure Assist — project report</title><style>${PALETTE}${DIFF_STYLES}${STYLES}</style></head>
<body>
  <h1>Project security report</h1>
  <div class="sub">${escapeHtml(report.scannedAt.toLocaleString())} · ${report.scannedCount} file${report.scannedCount === 1 ? "" : "s"} scanned${interactive ? "" : " · exported report (static)"}</div>

  <div class="score-row">
    <div class="score ${band}" id="projectScore">${report.score}</div>
    <div class="score-meta">
      <div class="score-label">project score (out of 100)</div>
      <div class="score-label" id="cleanLabel">${report.cleanCount} of ${report.scannedCount} files clean</div>
      <div class="score-label delta" id="sessionDelta"></div>
    </div>
    ${trend}
  </div>

  <div class="summary">
    <span class="pill critical">${report.counts.critical} critical</span>
    <span class="pill medium">${report.counts.medium} medium</span>
    <span class="pill low">${report.counts.low} low</span>
    <span class="pill">${report.totalFindings} total</span>
  </div>

  ${cweBreakdown}
  ${activityPanel}
  ${dismissedPanel}
  ${toolbar}
  ${filterBar}
  ${body}
  ${codeToggleScript}
  ${script}
</body>
</html>`;
}
