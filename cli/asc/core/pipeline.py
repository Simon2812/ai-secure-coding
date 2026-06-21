"""Analysis pipeline orchestration."""

from __future__ import annotations

from typing import Any, Dict

from asc.core.analyzer_client import run_static_analyzer
from asc.core.correlation import correlate_findings
from asc.core.input import AnalysisInput
from asc.core.model_client import run_model_analysis


def run_analysis_pipeline(
    analysis_input: AnalysisInput,
) -> Dict[str, Any]:
    """
    Run static analysis, model analysis and correlation.
    """

    static_result = run_static_analyzer(analysis_input)
    model_result = run_model_analysis(
        code=analysis_input.code,
        static_findings=static_result["raw_findings"],
    )

    intersections = correlate_findings(
        static_findings=static_result["findings"],
        model_findings=model_result["findings"],
    )

    return {
        "static_findings": static_result["raw_findings"],
        "model_findings": model_result["raw_response"].get(
            "vulnerabilities",
            [],
        ),
        "normalized_static_findings": static_result["findings"],
        "normalized_model_findings": model_result["findings"],
        "intersections": intersections,
        "model_response": model_result["raw_response"],
    }
