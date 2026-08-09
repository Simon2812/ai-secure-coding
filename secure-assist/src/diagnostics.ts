import * as vscode from "vscode";
import { Finding } from "./analyzer/types";
import { getCweInfo } from "./model/cweCatalog";

export function createDiagnosticCollection(): vscode.DiagnosticCollection {
  return vscode.languages.createDiagnosticCollection("secure-assist");
}

export function updateDiagnostics(
  collection: vscode.DiagnosticCollection,
  doc: vscode.TextDocument,
  findings: Finding[]
) {
  const diagnostics: vscode.Diagnostic[] = findings.map((finding) => {
    const line = Math.max(0, finding.line - 1);
    const col = Math.max(0, finding.column - 1);

    const start = new vscode.Position(line, col);
    const end = new vscode.Position(line, col + Math.max(1, finding.evidence.length));
    const range = new vscode.Range(start, end);

    // Enrich with the shared CWE catalog so the squiggle explains the class of
    // issue, not just the rule that fired.
    const info = getCweInfo(finding.cweId);
    const header = info ? `${finding.cweId} - ${info.title}` : finding.cweId;
    const extra = info?.recommendation ? `\n${info.recommendation}` : "";

    const diagnostic = new vscode.Diagnostic(
      range,
      `[${header}] ${finding.message}${extra}`,
      mapSeverity(finding.severity)
    );

    diagnostic.source = "Secure Assist";
    diagnostic.code = finding.ruleId;

    return diagnostic;
  });

  collection.set(doc.uri, diagnostics);
}

function mapSeverity(severity: Finding["severity"]): vscode.DiagnosticSeverity {
  switch (severity) {
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}