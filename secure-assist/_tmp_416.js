process.chdir("C:/Users/drozh/asc-main-dataset/secure-assist");
const { initAstAnalyzer, astAnalyzeCode } = require("./src/scripts/ast/astAnalyzer");
const fs = require("fs");
const path = require("path");
const REPO_ROOT = "C:/Users/drozh/asc-main-dataset";
async function main() {
  await initAstAnalyzer();
  const metaDir = REPO_ROOT + "/dataset/metadata/CWE-416";
  for (const file of fs.readdirSync(metaDir).sort()) {
    const meta = JSON.parse(fs.readFileSync(metaDir + "/" + file, "utf-8"));
    if (meta.vulnerabilities.length === 0) continue;
    const relPath = meta.path.startsWith("/") ? meta.path.slice(1) : meta.path;
    const codePath = REPO_ROOT + "/" + relPath;
    if (!fs.existsSync(codePath)) continue;
    const code = fs.readFileSync(codePath, "utf-8");
    const findings = astAnalyzeCode(code, codePath);
    if (findings.length === 0) {
      console.log("FN: " + meta.id + " [" + meta.language + "]");
    } else {
      const cwes = [...new Set(findings.map(f => f.cweId))].join(",");
      console.log("TP: " + meta.id + " [" + meta.language + "] -> " + cwes);
    }
  }
}
main().catch(console.error);