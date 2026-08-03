import * as path from "path";
import { Parser } from "web-tree-sitter";
import { Finding } from "../../analyzer/types";
import { initTreeSitter, PythonLang, JavaLang, CLang, newParser } from "./init";
import { analyzePython } from "./python";
import { analyzeJava } from "./java";
import { analyzeC } from "./c";

let parser: Parser | null = null;

export async function initAstAnalyzer(): Promise<void> {
  await initTreeSitter();
  parser = newParser();
}

export function astAnalyzeCode(code: string, filePath: string): Finding[] {
  if (!parser) throw new Error("AST analyzer not initialized");

  const ext = path.extname(filePath).toLowerCase();

  if (ext === ".py") {
    parser.setLanguage(PythonLang);
    const tree = parser.parse(code);
    if (!tree) return [];
    return analyzePython(code, filePath, tree);
  }

  if (ext === ".java") {
    parser.setLanguage(JavaLang);
    const tree = parser.parse(code);
    if (!tree) return [];
    return analyzeJava(code, filePath, tree);
  }

  if (ext === ".c" || ext === ".cpp" || ext === ".h") {
    parser.setLanguage(CLang);
    const tree = parser.parse(code);
    if (!tree) return [];
    return analyzeC(code, filePath, tree);
  }

  return [];
}
