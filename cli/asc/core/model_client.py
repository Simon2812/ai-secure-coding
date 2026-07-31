"""Model API client for the ASC analysis pipeline."""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from asc.core.errors import AscError


DEFAULT_MODEL_API_URL = "http://127.0.0.1:8000/analyze"
MODEL_API_ENV_VAR = "ASC_MODEL_API_URL"
DEFAULT_MODEL_TIMEOUT_SECONDS = 120


def run_model_analysis(
    code: str,
    static_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Call the model API and normalize its vulnerability output.

    The raw API response is preserved under `raw_response`.
    `findings` contains model vulnerabilities in a shape suitable
    for correlation and report construction.
    """

    response = _call_model_api(
        code=code,
        static_findings=static_findings,
    )

    vulnerabilities = response.get("vulnerabilities", [])

    if not isinstance(vulnerabilities, list):
        raise AscError("model API response vulnerabilities must be a list")

    return {
        "raw_response": response,
        "findings": [
            normalize_model_finding(index, vulnerability)
            for index, vulnerability in enumerate(vulnerabilities)
        ],
    }


def normalize_model_finding(
    index: int,
    vulnerability: Any,
) -> Dict[str, Any]:
    """
    Normalize one model vulnerability while preserving the raw object.
    """

    if not isinstance(vulnerability, dict):
        return {
            "source": "model",
            "index": index,
            "cwe": None,
            "start_line": None,
            "end_line": None,
            "fixes": [],
        }

    fixes = vulnerability.get("fixes", [])

    if not isinstance(fixes, list):
        fixes = []

    return {
        "source": "model",
        "index": index,
        "cwe": vulnerability.get("cwe"),
        "start_line": vulnerability.get("start_line"),
        "end_line": vulnerability.get("end_line"),
        "fixes": fixes,
    }


def _call_model_api(
    code: str,
    static_findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Send the analyzer findings and source code to the model API.
    """

    api_url = os.environ.get(
        MODEL_API_ENV_VAR,
        DEFAULT_MODEL_API_URL,
    )

    payload = json.dumps(
        {
            "code": code,
            "analysis": static_findings,
        }
    ).encode("utf-8")

    request = Request(
        api_url,
        data=payload,
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "asc-cli/0.1",
        },
        method="POST",
    )

    try:
        with urlopen(
            request,
            timeout=DEFAULT_MODEL_TIMEOUT_SECONDS,
        ) as response:
            body = response.read().decode("utf-8")
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise AscError(
            f"model API returned HTTP {error.code}: {detail}"
        ) from error
    except URLError as error:
        raise AscError(
            "failed to connect to model API at "
            f"{api_url}. Set {MODEL_API_ENV_VAR} if needed"
        ) from error
    except TimeoutError as error:
        raise AscError(
            "model API timed out after "
            f"{DEFAULT_MODEL_TIMEOUT_SECONDS} seconds"
        ) from error

    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as error:
        raise AscError("model API returned invalid JSON") from error

    if not isinstance(parsed, dict):
        raise AscError("model API response must be a JSON object")

    return parsed
