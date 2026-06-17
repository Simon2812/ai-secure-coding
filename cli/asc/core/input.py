"""Input resolution helpers for analysis commands."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from asc.core.errors import AscError


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

    If the value does not resolve to an existing file, it is treated
    as inline code. This keeps the public command compact:

        asc analyze app.py
        asc analyze "print('hello')"
    """

    candidate_path = Path(raw_input)

    if candidate_path.exists():
        if not candidate_path.is_file():
            raise AscError(
                f"input path is not a file: {candidate_path}"
            )

        code = candidate_path.read_text(encoding="utf-8")
        source_path = candidate_path.resolve()

        return AnalysisInput(
            input_type="file",
            code=code,
            filename=source_path.name,
            source_path=source_path,
        )

    if not raw_input.strip():
        raise AscError("inline code input cannot be empty")

    return AnalysisInput(
        input_type="inline",
        code=raw_input,
        filename=None,
        source_path=None,
    )
