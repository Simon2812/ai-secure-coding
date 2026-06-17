"""Implementation of the `asc analyze` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from asc.core.input import resolve_analysis_input
from asc.core.report import build_initial_report, default_report_path, write_report


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
            "a JSON report. Task 1.1 creates the report skeleton; "
            "later tasks will populate findings."
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

    This command deliberately does not call the static analyzer or
    model API yet. That belongs to Task 2.1. The goal here is to
    establish the public CLI behavior and stable report location.
    """

    analysis_input = resolve_analysis_input(args.input)
    output_path = (
        Path(args.output)
        if args.output
        else default_report_path(analysis_input)
    )

    report = build_initial_report(analysis_input)
    write_report(report, output_path)

    print(f"Report written to {output_path}")

    return 0
