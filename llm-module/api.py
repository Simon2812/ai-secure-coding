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
    fixes: List[FixModel]
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
