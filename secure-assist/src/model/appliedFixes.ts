import * as vscode from "vscode";
import { ModelFix, ModelVulnerability } from "./client";
import { findOriginRange, containsOrigin } from "./originMatch";

/**
 * Record of fixes the user applied, so they can be undone.
 *
 * VSCode's own undo only reaches as far as the editor's history: it is lost
 * when the file is closed, and it knows nothing about the finding the fix came
 * from, so undoing an edit that way leaves the finding gone and the counts
 * wrong. Reverting has to restore the code *and* put the finding back.
 *
 * The exact text on both sides is stored rather than re-derived. The applied
 * replacement was re-indented to match the file, so reconstructing it later
 * from the model's raw fix would not match what is actually on disk.
 */
export interface AppliedFix {
  /** Workspace-relative path, so the record survives a different checkout path. */
  file: string;
  cwe: string;
  /** Exact text that was replaced — what revert puts back. */
  originalText: string;
  /** Exact text that was written — what revert looks for. */
  insertedText: string;
  /** The model's fix, kept so the finding can be restored intact. */
  fix: ModelFix;
  /** Line the change started on, for display. */
  line: number;
  at: number;
}

const STORAGE_KEY = "secureAssist.appliedFixes";
let context: vscode.ExtensionContext | undefined;

export function initAppliedFixes(ctx: vscode.ExtensionContext): void {
  context = ctx;
}

export function listAppliedFixes(): AppliedFix[] {
  return context?.workspaceState.get<AppliedFix[]>(STORAGE_KEY) ?? [];
}

/** Applied fixes for one file, newest first. */
export function appliedFixesFor(relPath: string): AppliedFix[] {
  return listAppliedFixes()
    .filter((a) => a.file === relPath)
    .sort((a, b) => b.at - a.at);
}

export async function recordAppliedFix(entry: AppliedFix): Promise<void> {
  if (!context) return;
  await context.workspaceState.update(STORAGE_KEY, [...listAppliedFixes(), entry]);
}

/**
 * Applied fixes whose inserted text is still present in the file.
 *
 * Undoing a fix with the editor's own undo, or editing the line by hand, leaves
 * the record behind: nothing tells us the change went away. Showing it would
 * offer a Revert that cannot work and imply the file still carries a fix it does
 * not, so entries that can no longer be located are left out of the listing.
 * They are kept in storage rather than deleted, because a further undo can
 * bring the text back.
 */
export function appliedFixesIn(relPath: string, code: string): AppliedFix[] {
  return appliedFixesFor(relPath).filter((a) => containsOrigin(code, a.insertedText));
}

/** Identity for a record — a file plus the text that was inserted. */
function sameEntry(a: AppliedFix, file: string, insertedText: string): boolean {
  return a.file === file && a.insertedText === insertedText;
}

export async function forgetAppliedFix(file: string, insertedText: string): Promise<void> {
  if (!context) return;
  await context.workspaceState.update(
    STORAGE_KEY,
    listAppliedFixes().filter((a) => !sameEntry(a, file, insertedText))
  );
}

export async function clearAppliedFixes(): Promise<void> {
  await context?.workspaceState.update(STORAGE_KEY, []);
}

/**
 * Put the original code back.
 *
 * The inserted text is located with the same whitespace-tolerant matching used
 * to apply it, because the file may have been reformatted since. Returns the
 * restored vulnerability so the caller can add it back to the findings, or
 * undefined when the change can no longer be located — which means the code
 * has been edited further and reverting would corrupt it.
 */
export async function revertAppliedFix(
  entry: AppliedFix,
  uri: vscode.Uri
): Promise<ModelVulnerability | undefined> {
  const document = await vscode.workspace.openTextDocument(uri);
  const found = findOriginRange(document.getText(), entry.insertedText);
  if (!found) return undefined;

  const range = new vscode.Range(
    document.positionAt(found.start),
    document.positionAt(found.end)
  );

  const edit = new vscode.WorkspaceEdit();
  edit.replace(uri, range, entry.originalText);
  if (!(await vscode.workspace.applyEdit(edit))) return undefined;

  await forgetAppliedFix(entry.file, entry.insertedText);

  return {
    cwe: entry.cwe,
    fixes: [entry.fix],
    start_line: entry.line,
    end_line: entry.line,
  };
}
