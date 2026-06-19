"""Helpers for correlating static and model findings."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


NEARBY_LINE_DISTANCE = 2


def correlate_findings(
    static_findings: List[Dict[str, Any]],
    model_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Find static/model findings that likely describe the same issue.

    This helper intentionally does not assign final report confidence
    or IDs. Task 3 can use these intersections while building the
    prioritized report.
    """

    intersections = []

    for static_finding in static_findings:
        for model_finding in model_findings:
            match = _match_findings(
                static_finding,
                model_finding,
            )

            if match is None:
                continue

            intersections.append(
                {
                    "static_index": static_finding.get("index"),
                    "model_index": model_finding.get("index"),
                    "cwe": static_finding.get("cwe"),
                    "reason": match,
                }
            )

    return intersections


def _match_findings(
    static_finding: Dict[str, Any],
    model_finding: Dict[str, Any],
) -> Optional[str]:
    """
    Return a reason when two findings describe the same issue.
    """

    static_cwe = static_finding.get("cwe")
    model_cwe = model_finding.get("cwe")

    if not isinstance(static_cwe, str):
        return None

    if static_cwe != model_cwe:
        return None

    return _line_match(static_finding, model_finding)


def _line_match(
    static_finding: Dict[str, Any],
    model_finding: Dict[str, Any],
) -> Optional[str]:
    """
    Match by exact or nearby source line when the model returns ranges.
    """

    static_line = _as_int(static_finding.get("line"))
    start_line = _as_int(model_finding.get("start_line"))
    end_line = _as_int(model_finding.get("end_line"))

    if static_line is None or start_line is None:
        return None

    if end_line is None:
        end_line = start_line

    if start_line <= static_line <= end_line:
        return "same_cwe_and_overlapping_line"

    if (
        start_line - NEARBY_LINE_DISTANCE
        <= static_line
        <= end_line + NEARBY_LINE_DISTANCE
    ):
        return "same_cwe_and_nearby_line"

    return None


def _as_int(value: Any) -> Optional[int]:
    """
    Convert integer-like values to int.
    """

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    if isinstance(value, str) and value.isdigit():
        return int(value)

    return None
