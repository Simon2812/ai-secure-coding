from contextlib import asynccontextmanager
from typing import Any, List

from fastapi import (
    FastAPI,
    HTTPException,
)

from pydantic import BaseModel

from secure_model import (
    SecureCodingModel,
)


# Global singleton.
llm_model = (
    SecureCodingModel()
)


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
    fixes: List[
        FixModel
    ]


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

    vulnerabilities: List[
        VulnerabilityModel
    ]


class RegenerateFixRequest(BaseModel):
    """
    Alternative fix generation.
    """

    code: str
    analysis: Any

    cwe: str

    rejected_fixes: List[
        FixModel
    ]


class RegenerateFixResponse(BaseModel):
    """
    Alternative fix response.
    """

    cwe: str

    fixes: List[
        FixModel
    ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Load model once
    when container starts.
    """

    print(
        "Initializing "
        "LLM service..."
    )

    llm_model.load_model()

    llm_model.load_checkpoint(
        "from contextlib import asynccontextmanager
from typing import Any, List

from fastapi import (
    FastAPI,
    HTTPException,
)

from pydantic import BaseModel

from secure_model import (
    SecureCodingModel,
)


# Global singleton.
llm_model = (
    SecureCodingModel()
)


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
    fixes: List[
        FixModel
    ]


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

    vulnerabilities: List[
        VulnerabilityModel
    ]


class RegenerateFixRequest(BaseModel):
    """
    Alternative fix generation.
    """

    code: str
    analysis: Any

    cwe: str

    rejected_fixes: List[
        FixModel
    ]


class RegenerateFixResponse(BaseModel):
    """
    Alternative fix response.
    """

    cwe: str

    fixes: List[
        FixModel
    ]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Load model once
    when container starts.
    """

    print(
        "Initializing "
        "LLM service..."
    )

    llm_model.load_model()

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
    title=
        "AI Secure Coding API",

    version=
        "1.0",

    lifespan=
        lifespan,
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
    response_model=
        AnalyzeResponse,
)
def analyze(
    request: AnalyzeRequest,
):
    """
    Analyze source code.
    """

    try:

        return (
            llm_model.predict(
                code=
                    request.code,

                analysis=
                    request.analysis,
            )
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@app.post(
    "/regenerate-fix",
    response_model=
        RegenerateFixResponse,
)
def regenerate_fix(
    request: RegenerateFixRequest,
):
    """
    Generate alternative
    fixes for one CWE.
    """

    try:

        return (
            llm_model.regenerate_fix(
                code=
                    request.code,

                analysis=
                    request.analysis,

                cwe=
                    request.cwe,

                rejected_fixes=
                    request.rejected_fixes,
            )
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )"
    )

    print(
        "LLM service ready."
    )

    yield

    print(
        "LLM service shutting down..."
    )


app = FastAPI(
    title=
        "AI Secure Coding API",

    version=
        "1.0",

    lifespan=
        lifespan,
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
    response_model=
        AnalyzeResponse,
)
def analyze(
    request: AnalyzeRequest,
):
    """
    Analyze source code.
    """

    try:

        return (
            llm_model.predict(
                code=
                    request.code,

                analysis=
                    request.analysis,
            )
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@app.post(
    "/regenerate-fix",
    response_model=
        RegenerateFixResponse,
)
def regenerate_fix(
    request: RegenerateFixRequest,
):
    """
    Generate alternative
    fixes for one CWE.
    """

    try:

        return (
            llm_model.regenerate_fix(
                code=
                    request.code,

                analysis=
                    request.analysis,

                cwe=
                    request.cwe,

                rejected_fixes=
                    request.rejected_fixes,
            )
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )
