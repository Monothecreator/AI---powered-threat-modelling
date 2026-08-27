from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from parsers.architecture_parser import parse_architecture
from threat_engine.analyzer import analyze
from threat_engine.models import Architecture, SecurityReport

app = FastAPI(title="AI Threat Modelling Engineer", version="0.1.0")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


class AnalysisRequest(BaseModel):
    architecture: Architecture | dict = Field(..., description="Architecture document")


@app.get("/")
def root() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/status")
def status() -> dict[str, str]:
    return {
        "service": "AI Threat Modelling Engineer",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
        "analyze": "/v1/analyze",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/analyze", response_model=SecurityReport)
def analyze_architecture(request: AnalysisRequest) -> SecurityReport:
    try:
        architecture = parse_architecture(request.architecture)
        return analyze(architecture)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
