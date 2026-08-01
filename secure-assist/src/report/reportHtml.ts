import { ScanReport, FileReport } from "./scanner";
import { getCweInfo } from "../model/cweCatalog";
import { scoreBand, severityOf } from "./score";
import { buildTree, collapseSingleChildFolders, FolderNode } from "./tree";

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * The webview inherits VSCode's theme variables. A file opened in a browser has
 * none of them, so the export supplies concrete fallbacks for the same names.
 */
const STANDALONE_VARS = `
:root {
  --vscode-font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --vscode-font-size: 14px;
  --vscode-foreground: #1f2328;
  --vscode-editor-background: #ffffff;
  --vscode-editorWidget-background: #f6f8fa;
  --vscode-textCodeBlock-background: #f0f2f5;
  --vscode-descriptionForeground: #656d76;
  --vscode-panel-border: #d0d7de;
  --vscode-list-hoverBackground: #eef1f4;
  --vscode-editor-font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  --vscode-button-background: #1f6feb;
  --vscode-button-foreground: #ffffff;
  --vscode-button-secondaryBackground: #eef1f4;
  --vscode-button-secondaryForeground: #1f2328;
  --vscode-button-border: #d0d7de;
}
@media (prefers-color-scheme: dark) {
  :root {
    --vscode-foreground: #e6edf3;
    --vscode-editor-background: #0d1117;
    --vscode-editorWidget-background: #161b22;
    --vscode-textCodeBlock-background: #161b22;
    --vscode-descriptionForeground: #8b949e;
    --vscode-panel-border: #30363d;
    --vscode-list-hoverBackground: #1c2128;
    --vscode-button-secondaryBackground: #21262d;
    --vscode-button-secondaryForeground: #e6edf3;
    --vscode-button-border: #30363d;
  }
}
`;

const STYLES = `
:root { color-scheme: light dark; }
body {
  font-family: var(--vscode-font-family);
  font-size: var(--vscode-font-size);
  color: var(--vscode-foreground);
  background: var(--vscode-editor-background);
  padding: 24px 28px 48px;
  line-height: 1.5;
}
h1 { font-size: 1.5rem; font-weight: 500; margin: 0 0 4px; }
.sub { color: var(--vscode-descriptionForeground); font-size: 0.85rem; margin-bottom: 24px; }
.score-row { display: flex; align-items: center; gap: 20px; margin-bottom: 8px; }
.score { font-size: 3rem; font-weight: 600; line-height: 1; }
.score.good { color: #3fb950; }
.score.warning { color: #d29922; }
.score.critical { color: #f85149; }
.score-label { color: var(--vscode-descriptionForeground); font-size: 0.85rem; }
.summary { display: flex; gap: 10px; flex-wrap: wrap; margin: 16px 0 28px; }
.pill {
  border: 1px solid var(--vscode-panel-border);
  border-radius: 999px; padding: 4px 12px; font-size: 0.8rem;
}
.pill.critical { border-color: #f85149; color: #f85149; }
.pill.medium   { border-color: #d29922; color: #d29922; }
.pill.low      { border-color: #6e7681; color: var(--vscode-descriptionForeground); }
details {
  border: 1px solid var(--vscode-panel-border);
  border-radius: 6px; margin-bottom: 8px; background: var(--vscode-editorWidget-background);
}
details[open] { padding-bottom: 6px; }
summary {
  cursor: pointer; padding: 10px 14px; display: flex;
  align-items: center; gap: 12px; user-select: none;
}
summary::-webkit-details-marker { display: none; }
summary:hover { background: var(--vscode-list-hoverBackground); }
.file-path { flex: 1; font-family: var(--vscode-editor-font-family); font-size: 0.85rem; }
.file-score { font-weight: 600; font-variant-numeric: tabular-nums; }
.file-score.good { color: #3fb950; }
.file-score.warning { color: #d29922; }
.file-score.critical { color: #f85149; }
.clean { color: #3fb950; font-size: 0.8rem; }
.finding {
  margin: 0 14px 10px; padding: 12px 14px;
  border-left: 3px solid var(--vscode-panel-border);
  background: var(--vscode-editor-background); border-radius: 0 4px 4px 0;
}
.finding.critical { border-left-color: #f85149; }
.finding.medium   { border-left-color: #d29922; }
.finding.low      { border-left-color: #6e7681; }
/* Reported by the model but not by the static analyzer. */
.finding.ai-only { border-left-color: #a371f7; border-left-style: dashed; }
.badge-ai {
  font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em;
  color: #a371f7; border: 1px solid #a371f7; border-radius: 999px;
  padding: 1px 8px; white-space: nowrap;
}
.finding-head { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
.cwe { font-weight: 600; }
.loc { color: var(--vscode-descriptionForeground); font-size: 0.8rem; cursor: pointer; text-decoration: underline; }
.loc-static { color: var(--vscode-descriptionForeground); font-size: 0.8rem; }
.msg { margin: 6px 0; }
.rec { color: var(--vscode-descriptionForeground); font-size: 0.85rem; }
pre.evidence {
  font-family: var(--vscode-editor-font-family); font-size: 0.8rem;
  background: var(--vscode-textCodeBlock-background); padding: 8px 10px;
  border-radius: 4px; overflow-x: auto; margin: 8px 0 0;
}
.actions { margin-top: 10px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
button {
  font-family: inherit; font-size: 0.82rem; padding: 4px 12px; border-radius: 3px;
  border: 1px solid var(--vscode-button-border, transparent);
  background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);
  cursor: pointer;
}
button.primary { background: var(--vscode-button-background); color: var(--vscode-button-foreground); }
button:disabled { opacity: 0.5; cursor: default; }
.status { font-size: 0.8rem; color: var(--vscode-descriptionForeground); }
.toolbar { display: flex; gap: 8px; margin-bottom: 20px; }
.empty { color: var(--vscode-descriptionForeground); padding: 20px 0; }

/* Folder tree */
details.folder { background: transparent; border-color: var(--vscode-panel-border); }
details.folder > summary { font-weight: 500; }
.folder-icon { display: inline-block; transition: transform 0.12s ease; color: var(--vscode-descriptionForeground); }
details.folder[open] > summary .folder-icon { transform: rotate(90deg); }
.folder-name { flex: 1; }
.folder-body { padding: 0 10px 6px 22px; }
details.file { background: var(--vscode-editorWidget-background); }

/* Per-file toolbar */
.file-tools {
  display: flex; gap: 8px; align-items: center; flex-wrap: wrap;
  margin: 8px 14px 12px; padding-top: 10px;
  border-top: 1px solid var(--vscode-panel-border);
}
.verdict { font-size: 0.75rem; padding: 1px 8px; border-radius: 999px; border: 1px solid; }
.verdict.ok { color: #3fb950; border-color: #3fb950; }
.verdict.applied { color: #3fb950; border-color: #3fb950; background: rgba(63, 185, 80, 0.12); }
.verdict:empty { display: none; }
/* A finding whose fix has been applied stays visible but reads as resolved. */
.finding.fixed { opacity: 0.6; border-left-color: #3fb950 !important; }
.finding.fixed .cwe { text-decoration: line-through; }
.ai-findings:empty { display: none; }

/* Inline source viewer */
button.see-code { font-size: 0.78rem; }
.code-block {
  margin: 0 14px 12px; border: 1px solid var(--vscode-panel-border); border-radius: 4px;
  background: var(--vscode-textCodeBlock-background); overflow-x: auto;
  font-family: var(--vscode-editor-font-family); font-size: 0.78rem; line-height: 1.5;
  max-height: 460px; overflow-y: auto;
}
.code-line { display: flex; white-space: pre; }
.code-line.flagged { background: rgba(248, 81, 73, 0.14); border-left: 3px solid #f85149; }
.code-line:not(.flagged) { border-left: 3px solid transparent; }
.ln {
  flex: 0 0 3.2em; text-align: right; padding: 0 10px 0 6px;
  color: var(--vscode-descriptionForeground); user-select: none;
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
    <div class="actions" id="actions-${id}"></div>
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
export function renderCodeRows(code: string, flaggedLines: Iterable<number>): string {
  const flagged = new Set(flaggedLines);
  return code
    .split("\n")
    .map((line, i) => {
      const n = i + 1;
      const cls = flagged.has(n) ? "code-line flagged" : "code-line";
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

  // Clean files get the same tools: the model may still find something the
  // static analyzer missed, which is exactly where it adds value.
  return `<details class="file">
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
export function buildReportHtml(report: ScanReport, interactive: boolean): string {
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
        document.addEventListener('click', (e) => {
          const loc = e.target.closest('.loc');
          if (loc) {
            vscode.postMessage({ type: 'open', file: loc.dataset.file, line: Number(loc.dataset.line) });
            return;
          }
          const verify = e.target.closest('button.verify');
          if (verify) {
            verify.disabled = true;
            const idx = verify.dataset.index;
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
          const fix = e.target.closest('button.fix');
          if (fix) {
            vscode.postMessage({ type: 'fix', id: fix.dataset.id, file: fix.dataset.file, fixIndex: Number(fix.dataset.fixIndex) });
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
                verdict.textContent = 'AI confirmed';
                verdict.className = 'verdict ok';
              }
              const actions = document.getElementById('actions-' + r.id);
              if (actions && r.fixCount > 0) addFixButtons(actions, r.id, r.fixCount);
            });

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
          } else if (msg.type === 'fixApplied') {
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
              scoreEl.className = 'file-score ' +
                (msg.score >= 80 ? 'good' : msg.score >= 50 ? 'warning' : 'critical');
            }
          } else if (msg.type === 'verifyFailed') {
            if (status) status.textContent = msg.message || 'AI verification failed.';
            const btn = document.querySelector('button.verify[data-index="' + msg.index + '"]');
            if (btn) btn.disabled = false;
          }
        });
      </script>`
    : "";

  const toolbar = interactive
    ? `<div class="toolbar">
         <button id="rescan">Re-scan project</button>
         <button id="export">Export to HTML</button>
       </div>`
    : "";

  // The source viewer is pure DOM work, so it ships in the export as well.
  const codeToggleScript = `<script>
    document.addEventListener('click', (e) => {
      const btn = e.target.closest('button.see-code');
      if (!btn) return;
      const block = document.getElementById(btn.dataset.target);
      if (!block) return;
      const showing = !block.hasAttribute('hidden');
      if (showing) { block.setAttribute('hidden', ''); btn.textContent = 'See code'; }
      else { block.removeAttribute('hidden'); btn.textContent = 'Hide code'; }
    });
  </script>`;

  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Secure Assist — project report</title><style>${interactive ? "" : STANDALONE_VARS}${STYLES}</style></head>
<body>
  <h1>Project security report</h1>
  <div class="sub">${escapeHtml(report.scannedAt.toLocaleString())} · ${report.scannedCount} file${report.scannedCount === 1 ? "" : "s"} scanned${interactive ? "" : " · exported report (static)"}</div>

  <div class="score-row">
    <div class="score ${band}">${report.score}</div>
    <div>
      <div class="score-label">project score (out of 100)</div>
      <div class="score-label">${report.cleanCount} of ${report.scannedCount} files clean</div>
    </div>
  </div>

  <div class="summary">
    <span class="pill critical">${report.counts.critical} critical</span>
    <span class="pill medium">${report.counts.medium} medium</span>
    <span class="pill low">${report.counts.low} low</span>
    <span class="pill">${report.totalFindings} total</span>
  </div>

  ${toolbar}
  ${body}
  ${codeToggleScript}
  ${script}
</body>
</html>`;
}
