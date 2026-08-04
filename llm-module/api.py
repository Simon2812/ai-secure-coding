from contextlib import asynccontextmanager
from typing import Any, List, Optional

from fastapi import (
    FastAPI,
    HTTPException,
)
from pydantic import BaseModel

from evaluator import Evaluator
from model import SecureCodingModel


# Global singletons.
llm_model = SecureCodingModel()
origin_locator = Evaluator()


class FixModel(BaseModel):
    """
    One exact code replacement.
    """

    origin: str
    replacement: str


class VulnerabilityModel(BaseModel):
    """
    One detected vulnerability.
    """

    cwe: str
    # Defaulted rather than required: a detection the model could not write a
    # fix for is still worth returning, and an unexpected shape should degrade
    # to "no fix" instead of failing validation for the whole response.
    fixes: List[FixModel] = []
    start_line: Optional[int] = None
    end_line: Optional[int] = None


class AnalyzeRequest(BaseModel):
    """
    Full vulnerability analysis.
    """

    code: str
    analysis: Any


class AnalyzeResponse(BaseModel):
    """
    Full vulnerability response.
    """

    vulnerabilities: List[VulnerabilityModel]


"""
Keys the model has been observed to use in place of "cwe".

The checkpoint is deterministic but not perfectly consistent about its
schema; it sometimes labels the identifier "id". Left unmapped, response
validation rejects the whole reply and a correct detection is returned to
the caller as a 500.
"""
CWE_KEY_ALIASES = (
    "cwe",
    "id",
    "cwe_id",
    "cweId",
)


def normalize_cwe_key(
    vulnerability: dict,
):
    """
    Move whichever alias the model used into "cwe".
    Returns None when no identifier is present at all.
    """

    for key in CWE_KEY_ALIASES:
        value = vulnerability.get(key)

        if isinstance(value, str) and value.strip():
            normalized = dict(vulnerability)

            for alias in CWE_KEY_ALIASES:
                normalized.pop(alias, None)

            normalized["cwe"] = value.strip()

            return normalized

    return None


def normalize_fix_shape(
    vulnerability: dict,
):
    """
    Lift a flattened fix into the nested "fixes" list.

    The model sometimes emits the replacement inline on the vulnerability
    itself ({"cwe": ..., "origin": ..., "replacement": ...}) rather than
    nested under "fixes". Both carry the same information, but only the
    nested form validates, so the flat form is reshaped rather than lost.
    """

    if isinstance(vulnerability.get("fixes"), list):
        return vulnerability

    origin = vulnerability.get("origin")
    replacement = vulnerability.get("replacement")

    normalized = dict(vulnerability)
    normalized.pop("origin", None)
    normalized.pop("replacement", None)

    if isinstance(origin, str) and isinstance(replacement, str):
        normalized["fixes"] = [
            {
                "origin": origin,
                "replacement": replacement,
            }
        ]
    else:
        # A detection with no usable fix is still a detection.
        normalized["fixes"] = []

    return normalized


def add_origin_line_ranges(
    prediction: dict,
    code: str,
):
    """
    Expand vulnerabilities into one response entry per located
    fix occurrence. Unmatched fixes remain without line ranges.
    """

    if not isinstance(prediction, dict):
        return prediction

    vulnerabilities = prediction.get(
        "vulnerabilities",
        [],
    )

    if not isinstance(vulnerabilities, list):
        return prediction

    expanded_vulnerabilities = []

    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue

        vulnerability = normalize_cwe_key(
            vulnerability
        )

        # An entry with no usable identifier is dropped rather than
        # failing the whole response.
        if vulnerability is None:
            continue

        vulnerability = normalize_fix_shape(
            vulnerability
        )

        fixes = vulnerability.get(
            "fixes",
            [],
        )

        if not isinstance(fixes, list):
            expanded_vulnerabilities.append(vulnerability)
            continue

        added_entry = False

        for fix in fixes:
            if not isinstance(fix, dict):
                continue

            origin = fix.get("origin")

            if not isinstance(origin, str):
                expanded_vulnerabilities.append(
                    {
                        "cwe": vulnerability.get("cwe"),
                        "fixes": [fix],
                    }
                )
                added_entry = True
                continue

            line_ranges = origin_locator.find_origin_line_ranges(
                code,
                origin,
            )

            if not line_ranges:
                expanded_vulnerabilities.append(
                    {
                        "cwe": vulnerability.get("cwe"),
                        "fixes": [fix],
                    }
                )
                added_entry = True
                continue

            for start_line, end_line in line_ranges:
                added_entry = True
                expanded_vulnerabilities.append(
                    {
                        "cwe": vulnerability.get("cwe"),
                        "fixes": [fix],
                        "start_line": start_line,
                        "end_line": end_line,
                    }
                )

        if not added_entry:
            expanded_vulnerabilities.append(vulnerability)

    prediction["vulnerabilities"] = expanded_vulnerabilities

    return prediction


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Load model once
    when service starts.
    """

    print(
        "Initializing "
        "LLM service..."
    )

    llm_model.load_checkpoint(
        "Simon2812/secure-coding-model"
    )

    print(
        "LLM service ready."
    )

    yield

    print(
        "LLM service shutting down..."
    )


app = FastAPI(
    title="AI Secure Coding API",
    version="1.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    """
    Basic health check.
    """

    return {
        "status": "ok"
    }


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    response_model_exclude_none=True,
)
def analyze(request: AnalyzeRequest):
    """
    Analyze source code.
    """

    try:
        prediction = llm_model.predict(
            code=request.code,
            static_findings=request.analysis,
        )

        return add_origin_line_ranges(
            prediction=prediction,
            code=request.code,
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error
