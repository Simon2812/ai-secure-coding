import { Finding } from "../analyzer/types";
import { ModelVulnerability } from "./client";

// Ported from cli/asc/core/correlation.py so the extension and CLI agree on
// what "the same issue" means.
const NEARBY_LINE_DISTANCE = 2;

export type MatchReason =
  | "same_cwe_and_overlapping_line"
  | "same_cwe_and_nearby_line"
  /**
   * Same CWE in the same file, but at a different place. The two tools often
   * point at different ends of one flaw — the analyzer at the sink where it
   * becomes exploitable, the model at the construction that causes it — so
   * this still means "the model saw this issue", not "the model found another".
   */
  | "same_cwe_elsewhere_in_file";

export interface Intersection {
  staticIndex: number;
  modelIndex: number;
  cwe: string;
  reason: MatchReason;
}

/** How a finding was corroborated across the two analysis sources. */
export type Confirmation = "both" | "static-only" | "model-only";

export interface CorrelationResult {
  intersections: Intersection[];
  /** Indices of static findings also reported by the model. */
  confirmedStatic: Set<number>;
  /** Indices of model findings also reported by the static analyzer. */
  confirmedModel: Set<number>;
}

/** Same CWE and an overlapping (or nearby) line ⇒ likely the same issue. */
function matchReason(
  staticFinding: Finding,
  modelFinding: ModelVulnerability
): MatchReason | undefined {
  if (!staticFinding.cweId || staticFinding.cweId !== modelFinding.cwe) return undefined;

  const staticLine = staticFinding.line;
  const startLine = modelFinding.start_line;
  if (staticLine == null || startLine == null) return undefined;
  const endLine = modelFinding.end_line ?? startLine;

  if (startLine <= staticLine && staticLine <= endLine) {
    return "same_cwe_and_overlapping_line";
  }
  if (
    startLine - NEARBY_LINE_DISTANCE <= staticLine &&
    staticLine <= endLine + NEARBY_LINE_DISTANCE
  ) {
    return "same_cwe_and_nearby_line";
  }
  return undefined;
}

/**
 * Correlate static and model findings so the UI can show which issues were
 * confirmed by both sources versus reported by only one.
 */
export function correlateFindings(
  staticFindings: Finding[],
  modelFindings: ModelVulnerability[]
): CorrelationResult {
  const intersections: Intersection[] = [];
  const confirmedStatic = new Set<number>();
  const confirmedModel = new Set<number>();

  // Pass 1 — the confident match: same CWE at (or beside) the same line.
  staticFindings.forEach((staticFinding, staticIndex) => {
    modelFindings.forEach((modelFinding, modelIndex) => {
      const reason = matchReason(staticFinding, modelFinding);
      if (!reason) return;
      intersections.push({
        staticIndex,
        modelIndex,
        cwe: staticFinding.cweId,
        reason,
      });
      confirmedStatic.add(staticIndex);
      confirmedModel.add(modelIndex);
    });
  });

  // Pass 2 — same CWE elsewhere in the file. The tools disagree about *where* a
  // flaw lives (sink vs. the code that builds the unsafe value), so an unmatched
  // pair sharing a CWE is treated as the same issue rather than a new one.
  // Paired one-to-one so N static findings aren't all claimed by one model hit.
  staticFindings.forEach((staticFinding, staticIndex) => {
    if (confirmedStatic.has(staticIndex)) return;

    const modelIndex = modelFindings.findIndex(
      (m, i) => !confirmedModel.has(i) && m.cwe === staticFinding.cweId
    );
    if (modelIndex < 0) return;

    intersections.push({
      staticIndex,
      modelIndex,
      cwe: staticFinding.cweId,
      reason: "same_cwe_elsewhere_in_file",
    });
    confirmedStatic.add(staticIndex);
    confirmedModel.add(modelIndex);
  });

  return { intersections, confirmedStatic, confirmedModel };
}
