"""Finding selection helpers for the apply command."""

from __future__ import annotations

from typing import Any, Dict, List

from asc.core.errors import AscError


def select_findings(
    report: Dict[str, Any],
    requested_ids: List[str],
    select_all: bool,
) -> List[Dict[str, Any]]:
    """
    Select findings by user-provided IDs or --all.

    IDs are provided as separate command-line arguments:

        asc apply report.json 1 3 5
    """

    if select_all and requested_ids:
        raise AscError("use either finding ids or --all, not both")

    if not select_all and not requested_ids:
        raise AscError("specify finding ids or --all")

    findings = report["findings"]

    if select_all:
        return findings

    selected_ids = _parse_requested_ids(requested_ids)
    findings_by_id = {
        finding["id"]: finding
        for finding in findings
    }

    missing_ids = [
        finding_id
        for finding_id in selected_ids
        if finding_id not in findings_by_id
    ]

    if missing_ids:
        missing = ", ".join(
            str(finding_id)
            for finding_id in missing_ids
        )
        raise AscError(
            f"finding id does not exist in report: {missing}"
        )

    return [
        findings_by_id[finding_id]
        for finding_id in selected_ids
    ]


def _parse_requested_ids(raw_ids: List[str]) -> List[int]:
    """
    Parse and validate positive integer finding IDs.
    """

    parsed_ids = []
    seen_ids = set()

    for raw_id in raw_ids:
        try:
            finding_id = int(raw_id)
        except ValueError as error:
            raise AscError(
                f"finding id must be an integer: {raw_id}"
            ) from error

        if finding_id <= 0:
            raise AscError(
                f"finding id must be positive: {finding_id}"
            )

        if finding_id in seen_ids:
            raise AscError(
                f"finding id was provided more than once: {finding_id}"
            )

        parsed_ids.append(finding_id)
        seen_ids.add(finding_id)

    return parsed_ids
