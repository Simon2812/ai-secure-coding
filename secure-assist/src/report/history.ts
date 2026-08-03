import * as vscode from "vscode";

const STORAGE_KEY = "secureAssist.scanHistory";
const ACTIVITY_KEY = "secureAssist.activity";
const MAX_ENTRIES = 50;
const MAX_ACTIVITY = 200;

/** One completed project scan, kept so the report can show a trend. */
export interface ScanRecord {
  /** Epoch milliseconds. */
  at: number;
  score: number;
  findings: number;
  files: number;
}

export function loadHistory(context: vscode.ExtensionContext): ScanRecord[] {
  const stored = context.workspaceState.get<ScanRecord[]>(STORAGE_KEY);
  return Array.isArray(stored) ? stored : [];
}

/**
 * Append a scan to the workspace's history, trimming the oldest entries.
 * History is per workspace, so switching projects doesn't mix trends.
 */
export async function recordScan(
  context: vscode.ExtensionContext,
  record: ScanRecord
): Promise<ScanRecord[]> {
  const history = [...loadHistory(context), record].slice(-MAX_ENTRIES);
  await context.workspaceState.update(STORAGE_KEY, history);
  return history;
}

export async function clearHistory(context: vscode.ExtensionContext): Promise<void> {
  await context.workspaceState.update(STORAGE_KEY, []);
}

/**
 * Something the developer did to the project, kept so the report can show what
 * has happened rather than only the current state.
 */
export interface ActivityEvent {
  at: number;
  kind: "scan" | "fix" | "dismiss" | "restore";
  /** Workspace-relative path, where the event concerns one file. */
  file?: string;
  cwe?: string;
  /** Short human-readable detail, e.g. the score after a scan. */
  detail?: string;
}

export function loadActivity(context: vscode.ExtensionContext): ActivityEvent[] {
  const stored = context.workspaceState.get<ActivityEvent[]>(ACTIVITY_KEY);
  return Array.isArray(stored) ? stored : [];
}

export async function recordActivity(
  context: vscode.ExtensionContext,
  event: Omit<ActivityEvent, "at">
): Promise<ActivityEvent[]> {
  const activity = [...loadActivity(context), { ...event, at: Date.now() }].slice(
    -MAX_ACTIVITY
  );
  await context.workspaceState.update(ACTIVITY_KEY, activity);
  return activity;
}

export async function clearActivity(context: vscode.ExtensionContext): Promise<void> {
  await context.workspaceState.update(ACTIVITY_KEY, []);
}

/**
 * Inline SVG sparkline of past scores.
 *
 * Rendered as a self-contained SVG so it survives the static HTML export with
 * no scripts or external assets.
 */
export function sparklineSvg(scores: number[], width = 132, height = 30): string {
  if (scores.length < 2) return "";

  const padding = 3;
  const usableW = width - padding * 2;
  const usableH = height - padding * 2;

  // Always plot against the full 0-100 range so the slope reflects real change
  // rather than being exaggerated by an auto-fitted axis.
  const points = scores.map((score, i) => {
    const x = padding + (i / (scores.length - 1)) * usableW;
    const y = padding + (1 - Math.max(0, Math.min(100, score)) / 100) * usableH;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const last = scores[scores.length - 1];
  const first = scores[0];
  const stroke = last > first ? "#3fb950" : last < first ? "#f85149" : "#8b949e";
  const [lastX, lastY] = points[points.length - 1].split(",");

  return `<svg class="sparkline" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"
      role="img" aria-label="Project score over the last ${scores.length} scans">
    <polyline fill="none" stroke="${stroke}" stroke-width="1.5"
      stroke-linejoin="round" stroke-linecap="round" points="${points.join(" ")}" />
    <circle cx="${lastX}" cy="${lastY}" r="2.5" fill="${stroke}" />
  </svg>`;
}
