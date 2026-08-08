import * as assert from "assert";
import { containsOrigin, findOriginRange, groundVulnerabilities } from "../model/originMatch";

// Minimal vulnerability shape needed for origin-location tests.
interface TestVuln {
  cwe: string;
  fixes: { origin: string; replacement: string }[];
  start_line?: number;
  end_line?: number;
}

suite("model origin matching", () => {
  test("locates exact, whitespace-tolerant, and escaped-newline origins", () => {
    const code = "function run() {\n  const cmd = input.trim();\n  exec(cmd);\n}\n";

    // Exact snippets should map back to their real character offset.
    assert.deepStrictEqual(findOriginRange(code, "exec(cmd)")?.start, code.indexOf("exec(cmd)"));

    // Equivalent snippets with different spacing or escaped newlines should
    // still be located in the same source file.
    assert.ok(containsOrigin(code, "const cmd = input.trim(); exec(cmd);"));
    assert.ok(containsOrigin(code, "const cmd = input.trim();\\nexec(cmd);"));
  });

  test("discards hallucinated fixes and recovers line numbers from real origins", () => {
    const code = "line1\nexec(cmd)\nline3\n";

    // The first finding has no line number, but its origin exists in the file.
    // The second finding points to source text that is not present.
    const vulns: TestVuln[] = [
      {
        cwe: "CWE-78",
        fixes: [{ origin: "exec(cmd)", replacement: "execFile(cmd)" }],
      },
      {
        cwe: "CWE-89",
        fixes: [{ origin: "db.query(password)", replacement: "db.query(params)" }],
      },
    ];
    const { grounded, discarded } = groundVulnerabilities(vulns, code);

    // A finding with a real origin becomes usable after its line is recovered.
    assert.strictEqual(grounded.length, 1);
    assert.strictEqual(grounded[0].start_line, 2);

    // A finding with no matching source text is discarded.
    assert.strictEqual(discarded.length, 1);
    assert.strictEqual(discarded[0].cwe, "CWE-89");
  });
});
