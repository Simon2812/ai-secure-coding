import * as assert from "assert";
import * as vscode from "vscode";
import { Finding } from "../analyzer/types";
import {
  clearSuppressions,
  filterSuppressed,
  initSuppressions,
  lineTextAt,
  suppress,
} from "../report/suppressions";
import { filterDisabledCwes, filterDisabledCweVulns } from "../report/settings";
import { projectScore, scoreBand, scoreForFindings } from "../report/score";

function contextStub(): vscode.ExtensionContext {
  // Suppressions normally use VS Code workspace storage. The test uses an
  // in-memory store so the behavior can be checked without opening a project.
  const store = new Map<string, unknown>();
  return {
    workspaceState: {
      get: <T>(key: string, fallback?: T) => (store.has(key) ? store.get(key) : fallback) as T,
      update: async (key: string, value: unknown) => {
        store.set(key, value);
      },
    },
  } as unknown as vscode.ExtensionContext;
}

function finding(cweId: string, line: number): Finding {
  // Minimal finding object used by suppression, settings, and score helpers.
  return {
    cweId,
    ruleId: `${cweId}-test`,
    vulnerability: "test",
    severity: "high",
    message: "test finding",
    file: "app.py",
    line,
    column: 1,
    evidence: "evidence",
  };
}

async function setTestEnabledCwes(value: Record<string, boolean>): Promise<void> {
  // The test host may not have a workspace open, so the test writes the same
  // setting at the global level.
  await vscode.workspace
    .getConfiguration("secureAssist")
    .update("enabledCwes", value, vscode.ConfigurationTarget.Global);
}

suite("software state", function () {
  // VS Code setting updates can take longer than Mocha's default timeout.
  this.timeout(10000);

  setup(async () => {
    // Each test starts with no suppressions and the default enabled-CWE state.
    initSuppressions(contextStub());
    await clearSuppressions();
    await setTestEnabledCwes({});
  });

  teardown(async () => {
    await clearSuppressions();
    await setTestEnabledCwes({});
  });

  test("suppression follows normalized code text instead of line number", async () => {
    const file = "app.py";
    const original = "def run(cmd):\n    exec(cmd)\n";

    // Suppress the exact code text originally reported on line 2.
    await suppress(file, "CWE-78", lineTextAt(original, 2), 2);

    // Inserting a line above changes the line number but not the flagged code.
    const shifted = "# new header\n" + original;
    assert.deepStrictEqual(filterSuppressed([finding("CWE-78", 3)], file, shifted), []);

    // Editing the flagged line changes the suppression key, so it should be
    // reported again.
    const changed = "# new header\ndef run(cmd):\n    exec(cmd.strip())\n";
    assert.strictEqual(filterSuppressed([finding("CWE-78", 3)], file, changed).length, 1);
  });

  test("disabled CWE settings filter findings, model vulns, and score inputs", async () => {
    // Disabling a CWE removes it from both extension findings and generated
    // vulnerability records.
    await setTestEnabledCwes({ "CWE-78": false });

    const findings = [finding("CWE-78", 2), finding("CWE-328", 4)];
    const enabledFindings = filterDisabledCwes(findings);
    const enabledVulns = filterDisabledCweVulns([{ cwe: "CWE-78" }, { cwe: "CWE-328" }]);

    assert.deepStrictEqual(enabledFindings.map((item) => item.cweId), ["CWE-328"]);
    assert.deepStrictEqual(enabledVulns.map((item) => item.cwe), ["CWE-328"]);

    // The project score should be calculated from enabled findings only.
    assert.strictEqual(scoreForFindings(enabledFindings), 90);
    assert.strictEqual(projectScore([90, 100]), 95);
    assert.strictEqual(scoreBand(95), "good");
  });
});
