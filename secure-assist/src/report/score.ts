import { Finding } from "../analyzer/types";

/**
 * Points deducted per finding, by CWE severity.
 * Injection flaws cost the most; weak-crypto/memory issues less.
 */
const CWE_WEIGHTS: Record<string, number> = {
  "CWE-89": 30, // SQL injection
  "CWE-78": 30, // Command injection
  "CWE-22": 20, // Path traversal
  "CWE-321": 20, // Hard-coded crypto key
  "CWE-259": 15, // Hard-coded password
  "CWE-787": 15, // Out-of-bounds write
  "CWE-327": 10, // Broken cipher
  "CWE-328": 10, // Weak hash
  "CWE-416": 10, // Use after free
  "CWE-190": 10, // Integer overflow
};

const DEFAULT_WEIGHT = 10;

export function weightFor(cweId: string): number {
  return CWE_WEIGHTS[cweId] ?? DEFAULT_WEIGHT;
}

/** 0–100 score for a single file: 100 minus the weight of every finding. */
export function scoreForFindings(findings: Finding[]): number {
  const deduction = findings.reduce((sum, f) => sum + weightFor(f.cweId), 0);
  return Math.max(0, 100 - deduction);
}

/** Plain average of per-file scores; 100 when there is nothing to score. */
export function projectScore(fileScores: number[]): number {
  if (fileScores.length === 0) return 100;
  const total = fileScores.reduce((sum, s) => sum + s, 0);
  return Math.round(total / fileScores.length);
}

export type ScoreBand = "good" | "warning" | "critical";

export function scoreBand(score: number): ScoreBand {
  if (score >= 80) return "good";
  if (score >= 50) return "warning";
  return "critical";
}

/** Severity bucket used for the report's summary counts. */
export function severityOf(cweId: string): "critical" | "medium" | "low" {
  const weight = weightFor(cweId);
  if (weight >= 30) return "critical";
  if (weight >= 15) return "medium";
  return "low";
}
