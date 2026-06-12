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
    start_line: int


class AnalyzeResponse(BaseModel):
    """
    Full vulnerability response.
    """

    vulnerabilities: List[VulnerabilityModel]


def add_origin_line_ranges(
    prediction: dict,
    code: str,
    snippet_start_line: int,
):
    """
    Add source line ranges to vulnerabilities when their
    fix origins can be located in the submitted snippet.
    """

    if not isinstance(prediction, dict):
        return prediction

    vulnerabilities = prediction.get(
        "vulnerabilities",
        [],
    )

    if not isinstance(vulnerabilities, list):
        return prediction

    line_offset = snippet_start_line - 1

    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue

        fixes = vulnerability.get(
            "fixes",
            [],
        )

        if not isinstance(fixes, list):
            continue

        ranges = []

        for fix in fixes:
            if not isinstance(fix, dict):
                continue

            origin = fix.get("origin")

            if not isinstance(origin, str):
                continue

            line_range = origin_locator.find_origin_line_range(
                code,
                origin,
            )

            if line_range is not None:
                ranges.append(line_range)

        if ranges:
            vulnerability["start_line"] = (
                min(start for start, _ in ranges) +
                line_offset
            )
            vulnerability["end_line"] = (
                max(end for _, end in ranges) +
                line_offset
            )

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
            snippet_start_line=request.start_line,
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error
