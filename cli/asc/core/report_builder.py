"""Final report construction for ASC analysis output."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from asc.core.cwe_catalog import get_cwe_info, load_cwe_catalog
from asc.core.input import AnalysisInput
from asc.core.report import build_initial_report


LOW_CONFIDENCE_NOTE = (
    "Note: low-confidence findings do not include automatic fixes. "
    "Review them manually or use your IDE assistant to create a remediation."
)


def build_analysis_report(
    analysis_input: AnalysisInput,
    analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build the final report from pipeline analysis output.

    Findings are prioritized by confidence:
    - high: static and model findings intersect
    - medium: model-only findings
    - low: static-only findings
    """

    catalog = load_cwe_catalog()
    report = build_initial_report(analysis_input)

    findings = _build_prioritized_findings(
        analysis=analysis,
        catalog=catalog,
    )

    report["findings"] = [
        _with_finding_id(index, finding)
        for index, finding in enumerate(findings, start=1)
    ]

    if any(finding.get("confidence") == "Low" for finding in findings):
        report["notes"] = [LOW_CONFIDENCE_NOTE]
    else:
        report["notes"] = []

    return report


def _build_prioritized_findings(
    analysis: Dict[str, Any],
    catalog: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Build high, medium and low findings in priority order.
    """

    static_findings = _list_value(
        analysis.get("normalized_static_findings")
    )
    model_findings = _list_value(
        analysis.get("normalized_model_findings")
    )
    intersections = _list_value(
        analysis.get("intersections")
    )

    high_findings = []
    used_static_indexes: Set[int] = set()
    used_model_indexes: Set[int] = set()

    for intersection in intersections:
        static_index = intersection.get("static_index")
        model_index = intersection.get("model_index")

        static_finding = _finding_by_index(static_findings, static_index)
        model_finding = _finding_by_index(model_findings, model_index)

        if static_finding is None or model_finding is None:
            continue

        if (
            static_index in used_static_indexes
            or model_index in used_model_indexes
        ):
            continue

        used_static_indexes.add(static_index)
        used_model_indexes.add(model_index)

        high_findings.append(
            _build_high_finding(
                model_finding=model_finding,
                catalog=catalog,
            )
        )

    _mark_static_findings_covered_by_high_findings(
        intersections=intersections,
        used_static_indexes=used_static_indexes,
        used_model_indexes=used_model_indexes,
    )

    medium_findings = [
        _build_model_finding(
            model_finding=finding,
            catalog=catalog,
        )
        for finding in model_findings
        if finding.get("index") not in used_model_indexes
    ]

    low_findings = [
        _build_static_finding(
            static_finding=finding,
            catalog=catalog,
        )
        for finding in static_findings
        if finding.get("index") not in used_static_indexes
    ]

    return (
        _sort_by_line(high_findings) +
        _sort_by_line(medium_findings) +
        _sort_by_line(low_findings)
    )


def _mark_static_findings_covered_by_high_findings(
    intersections: List[Dict[str, Any]],
    used_static_indexes: Set[int],
    used_model_indexes: Set[int],
) -> None:
    """
    Mark every static finding covered by a high-confidence model finding.

    Static analyzers can emit multiple findings for the same vulnerable
    line or code path. Once one model finding becomes high confidence,
    all static findings correlated with that same model finding should
    be treated as covered instead of leaking into the low-confidence
    section as duplicates.
    """

    for intersection in intersections:
        model_index = intersection.get("model_index")
        static_index = intersection.get("static_index")

        if model_index not in used_model_indexes:
            continue

        if isinstance(static_index, int):
            used_static_indexes.add(static_index)


def _build_high_finding(
    model_finding: Dict[str, Any],
    catalog: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a high-confidence finding confirmed by both tools.
    """

    cwe = model_finding.get("cwe")

    return {
        "cwe": cwe,
        **_catalog_fields(catalog, cwe),
        "confidence": "High",
        "start_line": model_finding.get("start_line"),
        "end_line": model_finding.get("end_line"),
        "fixes": _fixes(model_finding),
    }


def _build_model_finding(
    model_finding: Dict[str, Any],
    catalog: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a medium-confidence model-only finding.
    """

    cwe = model_finding.get("cwe")

    return {
        "cwe": cwe,
        **_catalog_fields(catalog, cwe),
        "confidence": "Medium",
        "start_line": model_finding.get("start_line"),
        "end_line": model_finding.get("end_line"),
        "fixes": _fixes(model_finding),
    }


def _build_static_finding(
    static_finding: Dict[str, Any],
    catalog: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Build a low-confidence static-only finding.
    """

    cwe = static_finding.get("cwe")

    return {
        "cwe": cwe,
        **_catalog_fields(catalog, cwe),
        "confidence": "Low",
        "line": static_finding.get("line"),
        "evidence": static_finding.get("evidence"),
        "fixes": [],
    }


def _catalog_fields(
    catalog: Dict[str, Dict[str, Any]],
    cwe: Any,
) -> Dict[str, Any]:
    """
    Return report fields provided by the CWE catalog.
    """

    info = get_cwe_info(catalog, cwe)

    return {
        "title": info.get("title"),
        "severity": info.get("severity"),
        "summary": info.get("summary"),
        "impact": info.get("impact", []),
        "recommendation": info.get("recommendation"),
    }


def _with_finding_id(
    finding_id: int,
    finding: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Add the public finding id as the first report field.
    """

    return {
        "id": finding_id,
        **finding,
    }


def _fixes(model_finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return model fixes when present.
    """

    fixes = model_finding.get("fixes")

    if not isinstance(fixes, list):
        return []

    return [
        fix
        for fix in fixes
        if isinstance(fix, dict)
    ]


def _sort_by_line(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Sort findings by their location while keeping unknown lines last.
    """

    return sorted(
        findings,
        key=lambda finding: (
            _line_sort_value(
                finding.get("start_line")
                if "start_line" in finding
                else finding.get("line")
            ),
        ),
    )


def _line_sort_value(value: Any) -> int:
    """
    Convert line-like values into sortable integers.
    """

    if isinstance(value, bool):
        return 1_000_000_000

    if isinstance(value, int):
        return value

    if isinstance(value, str) and value.isdigit():
        return int(value)

    return 1_000_000_000


def _finding_by_index(
    findings: List[Dict[str, Any]],
    index: Any,
) -> Optional[Dict[str, Any]]:
    """
    Find a normalized finding by its pipeline index.
    """

    for finding in findings:
        if finding.get("index") == index:
            return finding

    return None


def _list_value(value: Any) -> List[Dict[str, Any]]:
    """
    Return a list value or an empty list.
    """

    if not isinstance(value, list):
        return []

    return [
        item
        for item in value
        if isinstance(item, dict)
    ]
