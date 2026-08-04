import * as vscode from "vscode";
import { Finding } from "../analyzer/types";

/** Every CWE the analyzer can report. Order drives the settings panel. */
export const ALL_CWES = [
  "CWE-89",
  "CWE-78",
  "CWE-22",
  "CWE-321",
  "CWE-259",
  "CWE-787",
  "CWE-327",
  "CWE-328",
  "CWE-416",
  "CWE-190",
] as const;

const CONFIG_SECTION = "secureAssist";
const ENABLED_KEY = "enabledCwes";

/**
 * Which CWEs are reported.
 *
 * Stored as a plain object in configuration so it is also editable through
 * VSCode's own settings UI; the panel is a nicer front end for the same value.
 * A CWE absent from the map is treated as enabled, so new rules are on by
 * default rather than silently ignored after an upgrade.
 */
export function enabledMap(): Record<string, boolean> {
  const stored = vscode.workspace
    .getConfiguration(CONFIG_SECTION)
    .get<Record<string, boolean>>(ENABLED_KEY, {});
  return stored && typeof stored === "object" ? stored : {};
}

export function isCweEnabled(cwe: string): boolean {
  return enabledMap()[cwe] !== false;
}

export async function setCweEnabled(cwe: string, enabled: boolean): Promise<void> {
  const next = { ...enabledMap(), [cwe]: enabled };
  await vscode.workspace
    .getConfiguration(CONFIG_SECTION)
    .update(ENABLED_KEY, next, vscode.ConfigurationTarget.Workspace);
}

export async function setAllCwes(enabled: boolean): Promise<void> {
  const next: Record<string, boolean> = {};
  for (const cwe of ALL_CWES) next[cwe] = enabled;
  await vscode.workspace
    .getConfiguration(CONFIG_SECTION)
    .update(ENABLED_KEY, next, vscode.ConfigurationTarget.Workspace);
}

/**
 * Drop findings for CWEs the user has turned off.
 *
 * Applied before scoring, so a disabled CWE stops counting against the project
 * score — a score that included categories the team has said it does not track
 * would be misleading.
 */
export function filterDisabledCwes(findings: Finding[]): Finding[] {
  const map = enabledMap();
  if (Object.keys(map).length === 0) return findings;
  return findings.filter((f) => map[f.cweId] !== false);
}

/** Same, for model findings. */
export function filterDisabledCweVulns<T extends { cwe: string }>(vulns: T[]): T[] {
  const map = enabledMap();
  if (Object.keys(map).length === 0) return vulns;
  return vulns.filter((v) => map[v.cwe] !== false);
}

/** Whether the analyzer re-runs as the file is edited. */
export function isLiveModeEnabled(): boolean {
  return vscode.workspace.getConfiguration(CONFIG_SECTION).get<boolean>("liveMode", true);
}

export async function setLiveMode(enabled: boolean): Promise<void> {
  await vscode.workspace
    .getConfiguration(CONFIG_SECTION)
    .update("liveMode", enabled, vscode.ConfigurationTarget.Workspace);
}
