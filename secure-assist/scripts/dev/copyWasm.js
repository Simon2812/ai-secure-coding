/**
 * Refresh the vendored tree-sitter WASM files.
 *
 * The extension loads its grammars from resources/wasm/ rather than from
 * node_modules, because a packaged .vsix does not ship node_modules. The
 * grammar packages are devDependencies purely so this script has something
 * to copy from; nothing imports them at runtime.
 *
 * Run after bumping any tree-sitter package:
 *   npm run wasm:refresh
 */

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const DEST = path.join(ROOT, "resources", "wasm");

const FILES = [
  ["web-tree-sitter", "web-tree-sitter.wasm"],
  ["tree-sitter-python", "tree-sitter-python.wasm"],
  ["tree-sitter-java", "tree-sitter-java.wasm"],
  ["tree-sitter-c", "tree-sitter-c.wasm"],
];

fs.mkdirSync(DEST, { recursive: true });

let copied = 0;
const missing = [];

for (const [pkg, file] of FILES) {
  const from = path.join(ROOT, "node_modules", pkg, file);
  if (!fs.existsSync(from)) {
    missing.push(`${pkg}/${file}`);
    continue;
  }
  fs.copyFileSync(from, path.join(DEST, file));
  const kb = Math.round(fs.statSync(from).size / 1024);
  console.log(`  ${file} (${kb} KB)`);
  copied++;
}

console.log(`\ncopied ${copied} of ${FILES.length} into resources/wasm/`);

if (missing.length) {
  console.error("\nmissing — run npm install first:");
  missing.forEach((m) => console.error(`  ${m}`));
  process.exit(1);
}
