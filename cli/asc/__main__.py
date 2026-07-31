"""Command-line entry point for the ASC tool."""

from __future__ import annotations

import argparse
import sys
from typing import Any, List, Optional

from asc.commands.analyze import add_analyze_parser
from asc.commands.apply import add_apply_parser
from asc.core.errors import AscError

APPLY_ALLOWED_FLAGS = {
    "-h",
    "--help",
    "-a",
    "--all",
}


class AscArgumentParser(argparse.ArgumentParser):
    """
    Argument parser with ASC-specific help text styling.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._positionals.title = "Positional arguments"
        self._optionals.title = "Optional arguments"
        self._rename_help_action()

    def _rename_help_action(self) -> None:
        """
        Capitalize the built-in help action description.
        """

        for action in self._actions:
            if "-h" in action.option_strings:
                action.help = "Show this help message and exit"
                return


def build_parser() -> argparse.ArgumentParser:
    """
    Build the top-level CLI parser.
    """

    parser = AscArgumentParser(
        prog="asc",
        description="AI Secure Coding command-line tool.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        parser_class=AscArgumentParser,
    )

    add_analyze_parser(subparsers)
    add_apply_parser(subparsers)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """
    Run the ASC CLI.

    Returns a process exit code so this function is easy to test
    and can also be used by the installed console script.
    """

    parser = build_parser()
    argv = sys.argv[1:] if argv is None else argv
    _validate_apply_option_tokens(argv)

    args, unknown_args = parser.parse_known_args(argv)

    if unknown_args:
        command_parser = getattr(
            args,
            "command_parser",
            parser,
        )
        command_parser.error(
            "unrecognized arguments: " + " ".join(unknown_args)
        )

    try:
        return args.handler(args)
    except AscError as error:
        command = getattr(args, "command", None)
        prefix = f"asc {command}" if command else "asc"
        print(f"{prefix}: error: {error}", file=sys.stderr)
        return 1


def _validate_apply_option_tokens(argv: List[str]) -> None:
    """
    Reject unsupported apply flags before argparse sees them.

    Argparse treats inputs such as `-ad` as `-a` with an attached
    argument and emits a confusing message. The apply command only
    accepts -h, --help, -a and --all as option-looking tokens.
    """

    if not argv or argv[0] != "apply":
        return

    for token in argv[1:]:
        if token in APPLY_ALLOWED_FLAGS:
            continue

        if token.startswith("-"):
            raise SystemExit(
                "asc apply: error: unrecognized arguments: "
                f"{token}"
            )


if __name__ == "__main__":
    raise SystemExit(main())
