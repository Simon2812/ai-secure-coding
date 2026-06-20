"""Implementation of the `asc analyze` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from asc.core.input import resolve_analysis_input
from asc.core.pipeline import run_analysis_pipeline
from asc.core.report import default_report_path, write_report
from asc.core.report_builder import build_analysis_report


def add_analyze_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    """
    Register the analyze command with the top-level parser.

    Usage:
        asc analyze path/to/file.py
        asc analyze "print('hello')"
        asc analyze path/to/file.py -o report.json
    """

    parser = subparsers.add_parser(
        "analyze",
        help="Analyze a source file or inline code snippet.",
        description=(
            "Analyze a source file or inline code snippet and create "
            "a prioritized JSON report."
        ),
    )

    parser.add_argument(
        "input",
        help=(
            "Path to a source file, or inline source code when the "
            "value does not point to an existing file."
        ),
    )

    parser.add_argument(
        "-o",
        "--output",
        help=(
            "Report output path. Defaults to report.json in the "
            "current working directory."
        ),
    )

    parser.set_defaults(
        handler=run_analyze,
        command_parser=parser,
    )

    return parser


def run_analyze(args: argparse.Namespace) -> int:
    """
    Resolve input and write the initial analysis report.

    The command runs the analysis pipeline and then builds a final
    prioritized report.
    """

    analysis_input = resolve_analysis_input(args.input)
    output_path = (
        Path(args.output)
        if args.output
        else default_report_path(analysis_input)
    )

    analysis = run_analysis_pipeline(analysis_input)
    report = build_analysis_report(
        analysis_input=analysis_input,
        analysis=analysis,
    )
    write_report(report, output_path)

    print(f"Report written to {output_path}")

    return 0
