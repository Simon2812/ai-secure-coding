import * as vscode from "vscode";
import { Finding } from "../analyzer/types";

const STORAGE_KEY = "secureAssist.suppressions";

/** One finding the developer marked as a false positive. */
export interface Suppression {
  /** Workspace-relative path, forward slashes. */
  file: string;
  cwe: string;
  /** Normalized text of the flagged line(s) — the identity of the finding. */
  code: string;
  /** Line number when it was dismissed. Informational only; not part of the key. */
  line?: number;
  at: number;
}

let context: vscode.ExtensionContext | undefined;

export function initSuppressions(ctx: vscode.ExtensionContext): void {
  context = ctx;
}

/**
 * Collapse whitespace so re-indenting or reformatting does not resurrect a
 * dismissed finding, while any change to the actual tokens does.
 */
function normalize(code: string): string {
  return code.replace(/\s+/g, " ").trim();
}

/**
 * Identity of a finding.
 *
 * Deliberately keyed on the *text* of the flagged line rather than its number:
 * inserting code above a dismissed finding shifts its line but must not bring
 * it back, whereas editing the line itself is new code and must be re-reported.
 */
function keyOf(file: string, cwe: string, code: string): string {
  return `${file}::${cwe}::${normalize(code)}`;
}

function load(): Suppression[] {
  const stored = context?.workspaceState.get<Suppression[]>(STORAGE_KEY);
  return Array.isArray(stored) ? stored : [];
}

export function listSuppressions(): Suppression[] {
  return load();
}

export function isSuppressed(file: string, cwe: string, code: string): boolean {
  const target = keyOf(file, cwe, code);
  return load().some((s) => keyOf(s.file, s.cwe, s.code) === target);
}

export async function suppress(
  file: string,
  cwe: string,
  code: string,
  line?: number
): Promise<void> {
  if (!context) return;
  if (isSuppressed(file, cwe, code)) return;
  const next = [...load(), { file, cwe, code: normalize(code), line, at: Date.now() }];
  await context.workspaceState.update(STORAGE_KEY, next);
}

/** What the user chose when asked to confirm a suppression. */
export type SuppressChoice = "suppress" | "explain" | "cancel";

/**
 * Confirm before silencing a finding.
 *
 * Suppression is not a fix: the code is unchanged, only the reporting stops.
 * Because a mistaken dismissal hides a real vulnerability indefinitely, the
 * consequence is stated plainly and asking the assistant first is offered as
 * an alternative to guessing.
 */
export async function confirmSuppression(
  cwe: string,
  snippet: string
): Promise<SuppressChoice> {
  const line = snippet.trim().split("\n")[0];
  const preview = line.length > 80 ? `${line.slice(0, 80)}…` : line;

  const choice = await vscode.window.showWarningMessage(
    `Stop reporting ${cwe} for this code?`,
    {
      modal: true,
      detail:
        `${preview}\n\n` +
        "This does not change the code. If the finding is real, the vulnerability " +
        "stays in your project and will not be reported again - unless you edit " +
        "this line or remove the suppression in Settings.\n\n" +
        "If you are not sure whether it is a false positive, ask the assistant first.",
    },
    "Suppress",
    "Ask the assistant"
  );

  if (choice === "Suppress") return "suppress";
  if (choice === "Ask the assistant") return "explain";
  return "cancel";
}

export async function unsuppress(file: string, cwe: string, code: string): Promise<void> {
  if (!context) return;
  const target = keyOf(file, cwe, code);
  const next = load().filter((s) => keyOf(s.file, s.cwe, s.code) !== target);
  await context.workspaceState.update(STORAGE_KEY, next);
}

export async function clearSuppressions(): Promise<void> {
  await context?.workspaceState.update(STORAGE_KEY, []);
}

/** Text of the lines a finding covers, used as its identity. */
export function lineTextAt(code: string, startLine: number, endLine = startLine): string {
  const lines = code.split("\n");
  const from = Math.max(0, startLine - 1);
  const to = Math.min(lines.length - 1, Math.max(from, endLine - 1));
  return lines.slice(from, to + 1).join("\n");
}

/** Drop static findings the developer has dismissed for this exact code. */
export function filterSuppressed(
  findings: Finding[],
  file: string,
  code: string
): Finding[] {
  if (load().length === 0) return findings;
  return findings.filter((f) => !isSuppressed(file, f.cweId, lineTextAt(code, f.line)));
}

/** Drop model findings the developer has dismissed for this exact code. */
export function filterSuppressedVulns<
  T extends { cwe: string; start_line?: number; end_line?: number }
>(vulns: T[], file: string, code: string): T[] {
  if (load().length === 0) return vulns;
  return vulns.filter((v) => {
    if (v.start_line == null) return true; // no location — cannot key it
    return !isSuppressed(file, v.cwe, lineTextAt(code, v.start_line, v.end_line ?? v.start_line));
  });
}
