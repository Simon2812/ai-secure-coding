"""Shared CWE catalog loading for report enrichment."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from asc.core.errors import AscError


def load_cwe_catalog() -> Dict[str, Dict[str, Any]]:
    """
    Load the shared CWE catalog used by CLI and extension code.
    """

    catalog_path = _catalog_path()

    try:
        catalog = json.loads(
            catalog_path.read_text(encoding="utf-8")
        )
    except FileNotFoundError as error:
        raise AscError(f"CWE catalog not found: {catalog_path}") from error
    except json.JSONDecodeError as error:
        raise AscError(f"CWE catalog is invalid JSON: {catalog_path}") from error
    except OSError as error:
        raise AscError(f"failed to read CWE catalog: {error}") from error

    if not isinstance(catalog, dict):
        raise AscError("CWE catalog must be a JSON object")

    return catalog


def get_cwe_info(
    catalog: Dict[str, Dict[str, Any]],
    cwe: Any,
) -> Dict[str, Any]:
    """
    Return display metadata for a CWE, with a conservative fallback.
    """

    if isinstance(cwe, str):
        info = catalog.get(cwe)

        if isinstance(info, dict):
            return info

        return {
            "title": cwe,
            "severity": "Unknown",
            "summary": "No catalog information is available for this CWE.",
            "impact": [],
            "recommendation": "Review the finding manually.",
        }

    return {
        "title": "Unknown CWE",
        "severity": "Unknown",
        "summary": "No CWE identifier is available for this finding.",
        "impact": [],
        "recommendation": "Review the finding manually.",
    }


def _catalog_path() -> Path:
    """
    Resolve the shared catalog path from the repository layout.
    """

    project_root = Path(__file__).resolve().parents[3]
    return project_root / "secure-assist" / "resources" / "cwe_catalog.json"
