import * as fs from "fs";
import * as path from "path";
import { Parser, Language } from "web-tree-sitter";

let initialized = false;
export let PythonLang: Language;
export let JavaLang: Language;
export let CLang: Language;

/**
 * Where the grammar and runtime WASM files live.
 *
 * They are vendored into `resources/wasm/` rather than read from
 * node_modules, because a packaged .vsix does not ship node_modules. The
 * node_modules path is kept as a fallback so a working tree that has not
 * copied them yet still runs.
 *
 * Only `web-tree-sitter` is ever imported. The native `tree-sitter` package
 * is not used at runtime, which is why the grammars' incompatible peer
 * versions of it do not matter.
 */
function wasmPath(fileName: string, nodeModulesDir: string): string {
  // __dirname is out/analyzer/ast, so three levels up is the extension root.
  const root = path.resolve(__dirname, "..", "..", "..");

  const vendored = path.join(root, "resources", "wasm", fileName);
  if (fs.existsSync(vendored)) return vendored;

  return path.join(root, "node_modules", nodeModulesDir, fileName);
}

export async function initTreeSitter(): Promise<void> {
  if (initialized) return;

  await Parser.init({
    locateFile(scriptName: string) {
      return wasmPath(scriptName, "web-tree-sitter");
    },
  });

  [PythonLang, JavaLang, CLang] = await Promise.all([
    Language.load(wasmPath("tree-sitter-python.wasm", "tree-sitter-python")),
    Language.load(wasmPath("tree-sitter-java.wasm", "tree-sitter-java")),
    Language.load(wasmPath("tree-sitter-c.wasm", "tree-sitter-c")),
  ]);

  initialized = true;
}

export function newParser(): Parser {
  return new Parser();
}
