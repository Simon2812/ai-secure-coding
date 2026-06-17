"""Command-line entry point for the ASC tool."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from asc.commands.analyze import add_analyze_parser
from asc.core.errors import AscError


def build_parser() -> argparse.ArgumentParser:
    """
    Build the top-level CLI parser.

    The CLI is intentionally small at this stage. Task 1.1 only
    exposes the analyze command; later tasks will add apply and
    connect analyze to the real static/model pipeline.
    """

    parser = argparse.ArgumentParser(
        prog="asc",
        description="AI Secure Coding command-line tool.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    add_analyze_parser(subparsers)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Run the ASC CLI.

    Returns a process exit code so this function is easy to test
    and can also be used by the installed console script.
    """

    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        return args.handler(args)
    except AscError as error:
        print(f"asc: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
