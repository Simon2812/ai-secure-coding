import { ModelFix } from "./client";

/**
 * Rendering for a proposed fix, shared by the fixes panel and the project
 * report so a change looks the same wherever it is reviewed.
 */

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

type DiffKind = "ctx" | "del" | "add";

/**
 * Line-level diff via longest common subsequence, so an unchanged line inside a
 * multi-line fix renders as context instead of a delete/add pair.
 */
function diffLines(before: string[], after: string[]): { kind: DiffKind; text: string }[] {
  const m = before.length;
  const n = after.length;
  const lcs: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      lcs[i][j] =
        before[i] === after[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const rows: { kind: DiffKind; text: string }[] = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (before[i] === after[j]) {
      rows.push({ kind: "ctx", text: before[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      rows.push({ kind: "del", text: before[i] });
      i++;
    } else {
      rows.push({ kind: "add", text: after[j] });
      j++;
    }
  }
  while (i < m) rows.push({ kind: "del", text: before[i++] });
  while (j < n) rows.push({ kind: "add", text: after[j++] });
  return rows;
}

function renderUnified(rows: { kind: DiffKind; text: string }[]): string {
  const marker: Record<DiffKind, string> = { ctx: " ", del: "-", add: "+" };
  return rows
    .map(
      (r) =>
        `<div class="dl ${r.kind}"><span class="mk">${marker[r.kind]}</span>` +
        `<span class="tx">${escapeHtml(r.text) || "&nbsp;"}</span></div>`
    )
    .join("");
}

/**
 * Pair removals with the additions that replace them so the two columns line
 * up: a run of deletions sits opposite the run of additions, padded with blanks
 * when the counts differ.
 */
function pairRows(
  rows: { kind: DiffKind; text: string }[]
): { left?: string; right?: string; ctx: boolean }[] {
  const paired: { left?: string; right?: string; ctx: boolean }[] = [];
  let dels: string[] = [];
  let adds: string[] = [];

  const flush = () => {
    for (let i = 0; i < Math.max(dels.length, adds.length); i++) {
      paired.push({ left: dels[i], right: adds[i], ctx: false });
    }
    dels = [];
    adds = [];
  };

  for (const row of rows) {
    if (row.kind === "del") dels.push(row.text);
    else if (row.kind === "add") adds.push(row.text);
    else {
      flush();
      paired.push({ left: row.text, right: row.text, ctx: true });
    }
  }
  flush();
  return paired;
}

function renderSplit(rows: { kind: DiffKind; text: string }[]): string {
  const cell = (text: string | undefined, side: "del" | "add", ctx: boolean) => {
    if (text === undefined) return `<div class="sc blank">&nbsp;</div>`;
    const cls = ctx ? "sc" : `sc ${side}`;
    return `<div class="${cls}">${escapeHtml(text) || "&nbsp;"}</div>`;
  };

  const body = pairRows(rows)
    .map((p) => `${cell(p.left, "del", p.ctx)}${cell(p.right, "add", p.ctx)}`)
    .join("");

  return `
    <div class="split">
      <div class="sh">Before</div>
      <div class="sh">After</div>
      ${body}
    </div>`;
}

/**
 * Both views are rendered; CSS shows whichever is selected. Pass `splitOnly`
 * where there is no toggle (the report renders one view inline).
 */
export function renderFixDiff(fix: ModelFix, splitOnly = false): string {
  const rows = diffLines(fix.origin.split("\n"), fix.replacement.split("\n"));
  if (splitOnly) return `<div class="view-split">${renderSplit(rows)}</div>`;
  return (
    `<div class="view-split">${renderSplit(rows)}</div>` +
    `<div class="view-unified diff">${renderUnified(rows)}</div>`
  );
}

/** Styles for the markup above. Both webviews inline this. */
export const DIFF_STYLES = `
.split {
  display: grid; grid-template-columns: 1fr 1fr; gap: 1px;
  border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
  background: var(--border); font-family: var(--mono); font-size: 0.8rem; line-height: 1.55;
}
.sh {
  background: var(--surface); color: var(--text-dim); font-family: var(--font);
  font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em;
  padding: 5px 10px;
}
.sc { background: var(--surface-2); padding: 0 10px; white-space: pre; overflow-x: auto; }
.sc.blank { background: var(--surface); }
.sc.del { background: rgba(240, 102, 95, 0.13); box-shadow: inset 2px 0 0 var(--bad); }
.sc.add { background: rgba(74, 194, 107, 0.13); box-shadow: inset 2px 0 0 var(--good); }

.diff {
  border: 1px solid var(--border); border-radius: 6px; overflow-x: auto;
  background: var(--surface-2); font-family: var(--mono); font-size: 0.8rem; line-height: 1.55;
}
.dl { display: flex; white-space: pre; border-left: 3px solid transparent; }
.dl .mk { flex: 0 0 1.6em; text-align: center; color: var(--text-dim); user-select: none; }
.dl .tx { flex: 1; padding-right: 12px; }
.dl.del { background: rgba(240, 102, 95, 0.13); border-left-color: var(--bad); }
.dl.add { background: rgba(74, 194, 107, 0.13); border-left-color: var(--good); }
.dl.del .mk { color: var(--bad); }
.dl.add .mk { color: var(--good); }
`;
