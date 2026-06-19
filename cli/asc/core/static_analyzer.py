"""Static analyzer integration for the ASC analysis pipeline."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Dict, List

from asc.core.errors import AscError
from asc.core.input import AnalysisInput


SUPPORTED_SUFFIXES = {
    ".c",
    ".cpp",
    ".java",
    ".py",
}

DEFAULT_ANALYZER_TIMEOUT_SECONDS = 60


def run_static_analyzer(
    analysis_input: AnalysisInput,
) -> Dict[str, Any]:
    """
    Run the TypeScript static analyzer and normalize its findings.

    The original analyzer output is preserved under `raw_findings`.
    `findings` contains a stable, source-neutral shape for later
    correlation and report construction.
    """

    source_path = _prepare_analyzer_source(analysis_input)

    try:
        raw_findings = _run_analyzer_for_path(source_path)
    finally:
        if analysis_input.source_path is None:
            source_path.unlink(missing_ok=True)

    return {
        "raw_findings": raw_findings,
        "findings": [
            normalize_static_finding(index, finding)
            for index, finding in enumerate(raw_findings)
        ],
    }


def normalize_static_finding(
    index: int,
    finding: Any,
) -> Dict[str, Any]:
    """
    Normalize one analyzer finding while preserving the raw object.
    """

    if not isinstance(finding, dict):
        return {
            "source": "static",
            "index": index,
            "cwe": None,
            "line": None,
            "column": None,
            "evidence": None,
            "raw": finding,
        }

    return {
        "source": "static",
        "index": index,
        "cwe": finding.get("cweId"),
        "rule_id": finding.get("ruleId"),
        "vulnerability": finding.get("vulnerability"),
        "severity": finding.get("severity"),
        "message": finding.get("message"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "column": finding.get("column"),
        "evidence": finding.get("evidence"),
        "raw": finding,
    }


def _prepare_analyzer_source(
    analysis_input: AnalysisInput,
) -> Path:
    """
    Return a file path that the analyzer can inspect.

    File inputs use their original path. Inline code is written to a
    temporary file with a conservative suffix guess, because the
    analyzer chooses language by extension.
    """

    if analysis_input.source_path is not None:
        suffix = analysis_input.source_path.suffix.lower()

        if suffix not in SUPPORTED_SUFFIXES:
            raise AscError(
                f"unsupported source file extension for analyzer: {suffix}"
            )

        return analysis_input.source_path

    suffix = _guess_inline_suffix(analysis_input.code)
    temp_file = tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        encoding="utf-8",
        delete=False,
    )

    with temp_file:
        temp_file.write(analysis_input.code)

    return Path(temp_file.name)


def _guess_inline_suffix(code: str) -> str:
    """
    Guess a supported analyzer suffix for inline code.

    This is intentionally lightweight and internal-only. Users still
    do not need to provide a language flag.
    """

    lowered = code.lower()

    if "public class " in lowered or "system.out." in lowered:
        return ".java"
    
    if (
        "#include <iostream>" in lowered
        or "std::" in lowered
        or "using namespace std" in lowered
        or "cout <<" in lowered
        or "cin >>" in lowered
        or "new " in lowered
        or "delete " in lowered
    ):
        return ".cpp"

    if "#include" in lowered or "int main" in lowered:
        return ".c"

    return ".py"


def _run_analyzer_for_path(source_path: Path) -> List[Dict[str, Any]]:
    """
    Execute analyzer_runner.ts and parse its JSON output.
    """

    project_root = Path(__file__).resolve().parents[3]
    analyzer_root = project_root / "secure-assist"
    analyzer_runner = (
        analyzer_root
        / "src"
        / "analyzer"
        / "analyzer_runner.ts"
    )

    if not analyzer_runner.exists():
        raise AscError(f"analyzer runner not found: {analyzer_runner}")

    try:
        result = subprocess.run(
            [
                "npx",
                "ts-node",
                str(analyzer_runner),
                str(source_path),
            ],
            cwd=analyzer_root,
            capture_output=True,
            text=True,
            timeout=DEFAULT_ANALYZER_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as error:
        raise AscError(
            "failed to run analyzer because npx was not found"
        ) from error
    except subprocess.TimeoutExpired as error:
        raise AscError(
            "static analyzer timed out after "
            f"{DEFAULT_ANALYZER_TIMEOUT_SECONDS} seconds"
        ) from error

    if result.returncode != 0:
        raise AscError(
            "static analyzer failed\n"
            f"STDOUT:\n{result.stdout}\n"
            f"STDERR:\n{result.stderr}"
        )

    try:
        findings = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AscError(
            "static analyzer returned invalid JSON"
        ) from error

    if not isinstance(findings, list):
        raise AscError("static analyzer output must be a JSON list")

    return findings
