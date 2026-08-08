import sys
from pathlib import Path

import pytest

# Allow pytest to import the local CLI package from the CLI folder.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from asc.core.errors import AscError
from asc.core.remediation import apply_selected_fixes
from asc.core.selection import select_findings


def _report(source, findings):
    """Create a minimal ASC report for apply-command safety checks."""

    return {
        "metadata": {"source_path": str(source)},
        "findings": findings,
    }


def _finding(finding_id, replacement, origin="dangerous(cmd)"):
    """Create a fixable finding that points to one source expression."""

    return {
        "id": finding_id,
        "confidence": "high",
        "start_line": 2,
        "end_line": 2,
        "fixes": [{"origin": origin, "replacement": replacement}],
    }


def test_invalid_finding_id_is_user_facing_error(tmp_path):
    """Selecting an id that is not in the report should give a clear error."""

    source = tmp_path / "app.py"
    report = _report(source, [_finding(1, "safe(cmd)")])

    with pytest.raises(AscError, match="finding id does not exist in report: 99"):
        select_findings(report, ["99"], select_all=False)


def test_overlapping_fixes_are_rejected_without_writing(tmp_path):
    """Overlapping selected fixes should be rejected before editing the file."""

    source = tmp_path / "app.py"
    original = "def run(cmd):\n    return dangerous(cmd)\n"
    source.write_text(original, encoding="utf-8")
    report = _report(
        source,
        [
            _finding(1, "safe_one(cmd)"),
            _finding(2, "safe_two(cmd)"),
        ],
    )

    with pytest.raises(AscError, match="selected fixes overlap"):
        apply_selected_fixes(report, report["findings"])

    # Rejection must be atomic: the original file content is preserved.
    assert source.read_text(encoding="utf-8") == original


def test_invalid_python_fix_is_rejected_without_writing(tmp_path):
    """A replacement that breaks Python syntax should not be written."""

    source = tmp_path / "app.py"
    original = "def run(cmd):\n    return dangerous(cmd)\n"
    source.write_text(original, encoding="utf-8")
    report = _report(source, [_finding(1, "if")])

    with pytest.raises(AscError, match="would make the Python file invalid"):
        apply_selected_fixes(report, report["findings"])

    # The source was valid before the replacement, so a syntax-breaking fix must
    # leave the file exactly as it was.
    assert source.read_text(encoding="utf-8") == original
