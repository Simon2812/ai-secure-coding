"""JSON report creation and persistence."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Any, Dict

from asc.core.errors import AscError
from asc.core.input import AnalysisInput


def default_report_path(analysis_input: AnalysisInput) -> Path:
    """
    Choose the default report path.

    When users do not pass -o, write report.json to the directory
    where they invoked the command. This keeps report placement
    predictable even when the analyzed file lives elsewhere.
    """

    return Path("report.json")


def build_initial_report(analysis_input: AnalysisInput) -> Dict[str, Any]:
    """
    Build the base report structure shared by analyze and apply.
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

    try:
        output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output_path.write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as error:
        raise AscError(
            f"failed to write report {output_path}: {error}"
        ) from error


def load_report(report_path: Path) -> Dict[str, Any]:
    """
    Load and validate an ASC report.

    The apply command relies on the report as its source of truth.
    This helper keeps all report structure errors in one place and
    raises user-facing messages through AscError.
    """

    if not report_path.exists():
        raise AscError(f"report file does not exist: {report_path}")

    if not report_path.is_file():
        raise AscError(f"report path is not a file: {report_path}")

    try:
        report = json.loads(
            report_path.read_text(encoding="utf-8-sig")
        )
    except json.JSONDecodeError as error:
        raise AscError(
            f"report is not valid JSON: {report_path}"
        ) from error
    except OSError as error:
        raise AscError(
            f"failed to read report {report_path}: {error}"
        ) from error

    _validate_report_structure(report)
    _validate_report_source_path(report)

    return report


def _validate_report_structure(report: Any) -> None:
    """
    Validate the minimal report structure needed by apply.
    """

    if not isinstance(report, dict):
        raise AscError("report must be a JSON object")

    metadata = report.get("metadata")
    if not isinstance(metadata, dict):
        raise AscError("report.metadata must be an object")

    findings = report.get("findings")
    if not isinstance(findings, list):
        raise AscError("report.findings must be a list")

    seen_ids = set()

    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            raise AscError(
                f"report finding at position {index} must be an object"
            )

        finding_id = finding.get("id")
        if not isinstance(finding_id, int):
            raise AscError(
                f"report finding at position {index} must have "
                "an integer id"
            )

        if finding_id <= 0:
            raise AscError(
                f"report finding id must be positive: {finding_id}"
            )

        if finding_id in seen_ids:
            raise AscError(
                f"report contains duplicate finding id: {finding_id}"
            )

        seen_ids.add(finding_id)


def _validate_report_source_path(report: Dict[str, Any]) -> None:
    """
    Validate source_path when the report points to a file.
    """

    metadata = report["metadata"]
    source_path = metadata.get("source_path")

    if source_path is None:
        raise AscError(
            "cannot apply fixes because report has no source file"
        )

    if not isinstance(source_path, str) or not source_path.strip():
        raise AscError("report.metadata.source_path must be a file path")

    path = _resolve_report_source_path(source_path)

    if not path.exists():
        raise AscError(
            f"source file from report does not exist: {path}"
        )

    if not path.is_file():
        raise AscError(
            f"source path from report is not a file: {path}"
        )

    metadata["source_path"] = str(path)


def _resolve_report_source_path(source_path: str) -> Path:
    """
    Resolve a report source path for the current operating system.

    Reports generated inside WSL store Windows files as /mnt/c/... paths.
    When the same report is later applied from Windows, translate that
    path to C:/... before checking whether the file exists.
    """

    stripped = source_path.strip()

    if os.name == "nt":
        normalized = stripped.replace("\\", "/")
        parts = normalized.split("/")

        if (
            len(parts) >= 4
            and parts[0] == ""
            and parts[1] == "mnt"
            and len(parts[2]) == 1
            and parts[2].isalpha()
        ):
            drive = parts[2].upper()
            return Path(f"{drive}:/" + "/".join(parts[3:]))

    return Path(stripped)
