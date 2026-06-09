import fs from "fs";
import { initAstAnalyzer } from "../scripts/ast/astAnalyzer";
import { analyzeCode } from "./analyze";

/**
 * Analyzer runner.
 *
 * Responsibilities:
 * - read source code provided
 * - invoke analyzeCode() (AST-based)
 * - print findings as JSON
 *
 * Used by the Python evaluator.
 */

const filePath = process.argv[2];

if (!filePath) {
    console.error(
        "Usage: node analyzer_runner.js <filePath>"
    );

    process.exit(1);
}

(async () => {
    await initAstAnalyzer();

    const code = fs.readFileSync(filePath, "utf8");
    const findings = analyzeCode(code, filePath);

    console.log(JSON.stringify(findings));
})();
