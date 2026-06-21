"""Automatic remediation support for ASC reports."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from asc.core.errors import AscError


LOW_CONFIDENCE_MESSAGE = (
    "Unable to apply fix for {finding_id}: low-confidence findings do "
    "not include automatic fixes. Review them manually or use your "
    "IDE assistant to create a remediation."
)


@dataclass(frozen=True)
class Replacement:
    """
    One planned code replacement.
    """

    finding_id: int
    start: int
    end: int
    replacement: str


def apply_selected_fixes(
    report: Dict[str, Any],
    selected_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Apply available fixes for selected report findings in-place.
    """

    source_path = Path(report["metadata"]["source_path"])

    try:
        code = source_path.read_text(encoding="utf-8")
    except OSError as error:
        raise AscError(
            f"failed to read source file {source_path}: {error}"
        ) from error

    replacements = []
    skipped = []

    for finding in selected_findings:
        finding_id = finding.get("id")

        if finding.get("confidence") == "low":
            skipped.append(
                LOW_CONFIDENCE_MESSAGE.format(finding_id=finding_id)
            )
            continue

        planned = _plan_finding_replacements(code, finding)

        if not planned:
            skipped.append(
                f"Unable to apply fix for {finding_id}: no automatic "
                "fix is available."
            )
            continue

        replacements.extend(planned)

    _validate_no_conflicts(replacements)

    if replacements:
        updated_code = _apply_replacements(code, replacements)
        _validate_updated_source(
            source_path=source_path,
            original_code=code,
            updated_code=updated_code,
        )

        try:
            source_path.write_text(updated_code, encoding="utf-8")
        except OSError as error:
            raise AscError(
                f"failed to write source file {source_path}: {error}"
            ) from error

    return {
        "source_path": str(source_path),
        "applied": len(replacements),
        "skipped": skipped,
    }


def _plan_finding_replacements(
    code: str,
    finding: Dict[str, Any],
) -> List[Replacement]:
    """
    Plan replacements for one medium/high confidence finding.
    """

    finding_id = finding.get("id")
    line_span = _line_range_to_span(
        code=code,
        start_line=finding.get("start_line"),
        end_line=finding.get("end_line"),
    )

    if line_span is None:
        raise AscError(
            f"finding {finding_id} has invalid start_line/end_line"
        )

    fixes = finding.get("fixes")

    if not isinstance(fixes, list):
        return []

    replacements = []

    for fix in fixes:
        if not isinstance(fix, dict):
            continue

        origin = fix.get("origin")
        replacement = fix.get("replacement")

        if not isinstance(origin, str) or not isinstance(replacement, str):
            continue

        spans = _find_origin_spans_in_line_range(
            code=code,
            origin=origin,
            line_span=line_span,
        )

        if not spans:
            spans = _find_origin_spans_in_code(
                code=code,
                origin=origin,
            )

        if not spans:
            spans = [line_span]

        for start, end in spans:
            replacements.append(
                Replacement(
                    finding_id=finding_id,
                    start=start,
                    end=end,
                    replacement=_indent_replacement_for_span(
                        code=code,
                        start=start,
                        replacement=replacement,
                    ),
                )
            )

    return replacements


def _find_origin_spans_in_line_range(
    code: str,
    origin: str,
    line_span: Tuple[int, int],
) -> List[Tuple[int, int]]:
    """
    Find exact or normalized origin matches inside a line range.
    """

    range_start, range_end = line_span
    fragment = code[range_start:range_end]

    exact_spans = _find_exact_spans(fragment, origin)

    if exact_spans:
        return [
            (range_start + start, range_start + end)
            for start, end in exact_spans
        ]

    normalized_spans = _find_normalized_spans(fragment, origin)

    return [
        (range_start + start, range_start + end)
        for start, end in normalized_spans
    ]


def _find_origin_spans_in_code(
    code: str,
    origin: str,
) -> List[Tuple[int, int]]:
    """
    Find exact or normalized origin matches anywhere in the source.

    This is used when the model provides the right origin but slightly
    wrong line numbers. Exact origin matching is still required before
    falling back to full-line replacement.
    """

    exact_spans = _find_exact_spans(code, origin)

    if exact_spans:
        return exact_spans

    return _find_normalized_spans(code, origin)


def _find_exact_spans(
    text: str,
    target: str,
) -> List[Tuple[int, int]]:
    """
    Find all exact target occurrences.
    """

    if not target:
        return []

    spans = []
    search_start = 0

    while True:
        match_start = text.find(target, search_start)

        if match_start == -1:
            break

        match_end = match_start + len(target)
        spans.append((match_start, match_end))
        search_start = match_end

    return spans


def _find_normalized_spans(
    text: str,
    target: str,
) -> List[Tuple[int, int]]:
    """
    Find normalized target occurrences in text.
    """

    normalized_target, _ = _build_normalized_text(target)

    if not normalized_target:
        return []

    normalized_text, span_map = _build_normalized_text(text)

    if not normalized_text or not span_map:
        return []

    spans = []
    search_start = 0

    while True:
        match_start = normalized_text.find(
            normalized_target,
            search_start,
        )

        if match_start == -1:
            break

        match_end = match_start + len(normalized_target)
        original_start = span_map[match_start][0]
        original_end = span_map[match_end - 1][1]
        spans.append((original_start, original_end))
        search_start = match_end

    return spans


def _build_normalized_text(
    text: str,
) -> Tuple[str, List[Tuple[int, int]]]:
    """
    Normalize whitespace and common escaped characters for matching.
    """

    normalized_parts = []
    span_map = []
    previous_was_space = False
    index = 0

    while index < len(text):
        char = text[index]

        if char == "\\" and index + 1 < len(text):
            next_char = text[index + 1]

            if next_char in {"n", "r", "t"}:
                if not previous_was_space:
                    normalized_parts.append(" ")
                    span_map.append((index, index + 2))
                    previous_was_space = True
                index += 2
                continue

            if next_char in {'"', "'", "\\"}:
                normalized_parts.append(next_char)
                span_map.append((index, index + 2))
                previous_was_space = False
                index += 2
                continue

        if char.isspace():
            if not previous_was_space:
                normalized_parts.append(" ")
                span_map.append((index, index + 1))
                previous_was_space = True
            index += 1
            continue

        normalized_parts.append(char)
        span_map.append((index, index + 1))
        previous_was_space = False
        index += 1

    leading_trim = 0

    while (
        leading_trim < len(normalized_parts)
        and normalized_parts[leading_trim] == " "
    ):
        leading_trim += 1

    trailing_trim = len(normalized_parts)

    while (
        trailing_trim > leading_trim
        and normalized_parts[trailing_trim - 1] == " "
    ):
        trailing_trim -= 1

    return (
        "".join(normalized_parts[leading_trim:trailing_trim]),
        span_map[leading_trim:trailing_trim],
    )


def _line_range_to_span(
    code: str,
    start_line: Any,
    end_line: Any,
) -> Optional[Tuple[int, int]]:
    """
    Convert 1-based start/end lines to a character span.
    """

    start = _as_positive_int(start_line)
    end = _as_positive_int(end_line)

    if start is None:
        return None

    if end is None:
        end = start

    if end < start:
        return None

    line_spans = _line_spans(code)

    if start > len(line_spans) or end > len(line_spans):
        return None

    return (
        line_spans[start - 1][0],
        line_spans[end - 1][1],
    )


def _line_spans(code: str) -> List[Tuple[int, int]]:
    """
    Return character spans for every line, preserving line endings.
    """

    spans = []
    offset = 0

    for line in code.splitlines(keepends=True):
        start = offset
        offset += len(line)
        spans.append((start, offset))

    if not spans:
        spans.append((0, 0))

    return spans


def _as_positive_int(value: Any) -> Optional[int]:
    """
    Convert positive integer-like values to int.
    """

    if isinstance(value, bool):
        return None

    if isinstance(value, int) and value > 0:
        return value

    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        return parsed if parsed > 0 else None

    return None


def _validate_no_conflicts(replacements: List[Replacement]) -> None:
    """
    Prevent overlapping replacements before modifying the source file.
    """

    ordered = sorted(
        replacements,
        key=lambda item: (item.start, item.end),
    )

    previous = None

    for replacement in ordered:
        if previous is not None and replacement.start < previous.end:
            raise AscError(
                "selected fixes overlap between findings "
                f"{previous.finding_id} and {replacement.finding_id}"
            )

        previous = replacement


def _apply_replacements(
    code: str,
    replacements: List[Replacement],
) -> str:
    """
    Apply replacements from the end of the file toward the start.
    """

    updated = code

    for replacement in sorted(
        replacements,
        key=lambda item: item.start,
        reverse=True,
    ):
        updated = (
            updated[:replacement.start] +
            replacement.replacement +
            updated[replacement.end:]
        )

    return updated


def _indent_replacement_for_span(
    code: str,
    start: int,
    replacement: str,
) -> str:
    """
    Preserve surrounding indentation for multi-line replacements.

    Model fixes usually omit the indentation that already exists
    before the matched origin. The first replacement line inherits
    that prefix from the original source; following replacement lines
    need it added explicitly.
    """

    if "\n" not in replacement:
        return replacement

    line_start = code.rfind("\n", 0, start) + 1
    prefix = code[line_start:start]

    if not prefix or not prefix.isspace():
        return replacement

    lines = replacement.splitlines(keepends=True)

    return "".join(
        line if index == 0 or not line.strip() else prefix + line
        for index, line in enumerate(lines)
    )


def _validate_updated_source(
    source_path: Path,
    original_code: str,
    updated_code: str,
) -> None:
    """
    Prevent writing broken source when lightweight validation is available.
    """

    if source_path.suffix.lower() != ".py":
        if source_path.suffix.lower() == ".java":
            _validate_updated_java(
                source_path=source_path,
                original_code=original_code,
                updated_code=updated_code,
            )

        return

    try:
        ast.parse(original_code)
    except SyntaxError:
        return

    try:
        ast.parse(updated_code)
    except SyntaxError as error:
        raise AscError(
            "automatic fixes would make the Python file invalid; "
            f"no changes were written: {error.msg} at line {error.lineno}"
        ) from error


def _validate_updated_java(
    source_path: Path,
    original_code: str,
    updated_code: str,
) -> None:
    """
    Prevent writing Java that fails standalone compilation.

    Dataset files often contain public classes whose names do not match
    the dataset filename. Compile temporary copies using the public class
    name, and only enforce validation when the original source compiles
    in the same lightweight standalone mode.
    """

    javac = shutil.which("javac")

    if javac is None:
        return

    original_result = _compile_java_source(
        javac=javac,
        source_path=source_path,
        code=original_code,
    )

    if original_result.returncode != 0:
        return

    updated_result = _compile_java_source(
        javac=javac,
        source_path=source_path,
        code=updated_code,
    )

    if updated_result.returncode == 0:
        return

    details = updated_result.stderr.strip() or updated_result.stdout.strip()

    raise AscError(
        "automatic fixes would make the Java file fail compilation; "
        f"no changes were written:\n{details}"
    )


def _compile_java_source(
    javac: str,
    source_path: Path,
    code: str,
) -> subprocess.CompletedProcess[str]:
    """
    Compile Java code in a temporary directory.
    """

    class_name = _java_compile_unit_name(
        source_path=source_path,
        code=code,
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        java_file = tmp_path / f"{class_name}.java"

        java_file.write_text(
            code,
            encoding="utf-8",
        )

        return subprocess.run(
            [
                javac,
                "-d",
                str(tmp_path),
                str(java_file),
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )


def _java_compile_unit_name(
    source_path: Path,
    code: str,
) -> str:
    """
    Pick the filename javac expects for a Java compilation unit.
    """

    match = re.search(
        r"\bpublic\s+(?:final\s+|abstract\s+)?"
        r"(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)",
        code,
    )

    if match:
        return match.group(1)

    return source_path.stem
