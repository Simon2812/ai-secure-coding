import { Finding } from "./types";
import { initAstAnalyzer, astAnalyzeCode } from "../scripts/ast/astAnalyzer";

export { initAstAnalyzer };

export function analyzeCode(code: string, filePath: string): Finding[] {
  return astAnalyzeCode(code, filePath);
}
