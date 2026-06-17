"""JSON report creation and persistence."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict

from asc.core.input import AnalysisInput


def default_report_path(analysis_input: AnalysisInput) -> Path:
    """
    Choose the default report path.

    File input writes the report next to the analyzed file. Inline
    input writes to report.json in the current working directory.
    """

    if analysis_input.source_path is not None:
        return analysis_input.source_path.parent / "report.json"

    return Path("report.json")


def build_initial_report(analysis_input: AnalysisInput) -> Dict[str, Any]:
    """
    Build the Task 1.1 report skeleton.

    Later tasks will populate `findings` with correlated static/model
    vulnerabilities. Keeping the skeleton stable now makes the apply
    command easier to build later.
    """

    generated_at = (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

    return {
        "metadata": {
            "tool": "asc",
            "schema_version": "1.0",
            "generated_at": generated_at,
            "input_type": analysis_input.input_type,
            "filename": analysis_input.filename,
            "source_path": (
                str(analysis_input.source_path)
                if analysis_input.source_path is not None
                else None
            ),
        },
        "findings": [],
    }


def write_report(
    report: Dict[str, Any],
    output_path: Path,
) -> None:
    """
    Write a report as formatted JSON.

    Parent directories are created so users can pass paths such as
    `-o reports/report.json` without preparing the folder first.
    """

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )
