import json
import sys
from pathlib import Path

# Allow pytest to import the local CLI package from the cli folder.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from asc.__main__ import main


def test_analyze_then_apply_updates(tmp_path, monkeypatch):
    """Verify the main CLI workflow from report creation to applying a fix
    using mocked analysis pipeline."""

    # The test source contains one command-execution call that the prepared
    # analysis result will report as a fixable finding.
    source = tmp_path / "app.py"
    source.write_text(
        "import os\n\n"
        "def run(user_input):\n"
        "    return os.system(user_input)\n",
        encoding="utf-8",
    )
    report_path = tmp_path / "report.json"

    def fake_pipeline(_analysis_input):
        # The pipeline result contains one static finding and one matching
        # generated finding. Their intersection should become a high-confidence
        # report item with finding id 1 and an automatic replacement.
        return {
            "normalized_static_findings": [
                {"index": 0, "cwe": "CWE-78", "line": 4, "evidence": "os.system(user_input)"}
            ],
            "normalized_model_findings": [
                {
                    "index": 0,
                    "cwe": "CWE-78",
                    "start_line": 4,
                    "end_line": 4,
                    "fixes": [
                        {
                            "origin": "os.system(user_input)",
                            "replacement": "subprocess.run([user_input], check=True).returncode",
                        }
                    ],
                }
            ],
            "intersections": [{"static_index": 0, "model_index": 0}],
        }

    monkeypatch.setattr("asc.commands.analyze.run_analysis_pipeline", fake_pipeline)

    # The analyze command should write a valid report with metadata and ids.
    assert main(["analyze", str(source), "-o", str(report_path)]) == 0

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["metadata"]["source_path"] == str(source.resolve())
    assert report["findings"][0]["id"] == 1
    assert report["findings"][0]["confidence"] == "high"

    # The apply command should read the report and replace only the vulnerable
    # expression selected by the finding.
    assert main(["apply", str(report_path), "1"]) == 0

    updated = source.read_text(encoding="utf-8")
    assert "subprocess.run([user_input], check=True).returncode" in updated
    assert "os.system(user_input)" not in updated
