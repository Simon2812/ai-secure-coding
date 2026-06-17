"""Input resolution helpers for analysis commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from asc.core.errors import AscError

INLINE_CODE_MARKERS = {
    "\n",
    "\r",
    " ",
    "\t",
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    "=",
    ":",
    ";",
    ".",
    ",",
    "'",
    '"',
    "#",
    "/",
    "\\",
    "<",
    ">",
    "+",
    "-",
    "*",
    "%",
}


@dataclass(frozen=True)
class AnalysisInput:
    """
    Normalized representation of the user's analyze input.

    `source_path` is present only for file inputs. The report keeps
    both `filename` for display and `source_path` for future apply
    support.
    """

    input_type: str
    code: str
    filename: Optional[str]
    source_path: Optional[Path]


def resolve_analysis_input(raw_input: str) -> AnalysisInput:
    """
    Treat the analyze argument as a file when it exists.

    If the value does not resolve to an existing file, it is accepted
    as inline code only when it looks like source text. This keeps
    accidental inputs such as `asc analyze 22` from silently creating
    a report.

        asc analyze app.py
        asc analyze "print('hello')"
    """

    candidate_path = Path(raw_input)

    if candidate_path.exists():
        if not candidate_path.is_file():
            raise AscError(
                f"input path is not a file: {candidate_path}"
            )

        try:
            code = candidate_path.read_text(encoding="utf-8")
        except OSError as error:
            raise AscError(
                f"failed to read input file {candidate_path}: {error}"
            ) from error

        source_path = candidate_path.resolve()

        return AnalysisInput(
            input_type="file",
            code=code,
            filename=source_path.name,
            source_path=source_path,
        )

    if not raw_input.strip():
        raise AscError("inline code input cannot be empty")

    if not _looks_like_inline_code(raw_input):
        raise AscError(
            "input is not an existing file and does not look like "
            "inline code. Pass a valid file path or a code snippet, "
            "for example: asc analyze \"print('hello')\""
        )

    return AnalysisInput(
        input_type="inline",
        code=raw_input,
        filename=None,
        source_path=None,
    )


def _looks_like_inline_code(raw_input: str) -> bool:
    """
    Return whether a non-file argument looks like inline source code.

    Shells remove quotation marks before Python receives arguments,
    so the CLI cannot know whether the user typed `22` or `"22"`.
    A small syntax-marker check gives safer behavior without adding
    explicit --file/--code flags.
    """

    return any(
        marker in raw_input
        for marker in INLINE_CODE_MARKERS
    )
