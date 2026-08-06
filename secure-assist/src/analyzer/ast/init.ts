import * as path from "path";
import { Parser, Language } from "web-tree-sitter";

let initialized = false;
export let PythonLang: Language;
export let JavaLang: Language;
export let CLang: Language;

export async function initTreeSitter(): Promise<void> {
  if (initialized) return;

  await Parser.init({
    locateFile(scriptName: string) {
      return path.resolve(__dirname, "..", "..", "..", "node_modules", "web-tree-sitter", scriptName);
    },
  });

  const wasmBase = path.resolve(__dirname, "..", "..", "..", "node_modules");

  [PythonLang, JavaLang, CLang] = await Promise.all([
    Language.load(path.join(wasmBase, "tree-sitter-python", "tree-sitter-python.wasm")),
    Language.load(path.join(wasmBase, "tree-sitter-java", "tree-sitter-java.wasm")),
    Language.load(path.join(wasmBase, "tree-sitter-c", "tree-sitter-c.wasm")),
  ]);

  initialized = true;
}

export function newParser(): Parser {
  return new Parser();
}
