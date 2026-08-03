import type { Node } from "web-tree-sitter";
import { Finding, Severity } from "../../analyzer/types";

export function makeAstFinding(args: {
  cweId: string;
  ruleId: string;
  vulnerability: string;
  severity: Severity;
  message: string;
  filePath: string;
  node: Node;
  code: string;
}): Finding {
  return {
    cweId: args.cweId,
    ruleId: args.ruleId,
    vulnerability: args.vulnerability,
    severity: args.severity,
    message: args.message,
    file: args.filePath,
    line: args.node.startPosition.row + 1,
    column: args.node.startPosition.column + 1,
    evidence: args.node.text.slice(0, 120),
  };
}
