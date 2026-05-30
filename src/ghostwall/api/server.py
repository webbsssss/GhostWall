import os
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from ghostwall.core.pipeline import DetectionPipeline
from ghostwall.core.types import DetectionResult


pipeline: Optional[DetectionPipeline] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global pipeline
    pipeline = DetectionPipeline()
    yield


app = FastAPI(title="GhostWall", lifespan=lifespan)


class ScanRequest(BaseModel):
    text: str
    session_id: Optional[str] = None


class ScanResponse(BaseModel):
    is_malicious: bool
    risk_level: str
    final_label: str
    confidence: float
    latency_ms: float
    triggered_layers: list[str]


@app.post("/scan", response_model=ScanResponse)
async def scan(req: ScanRequest):
    if not pipeline:
        raise HTTPException(status_code=503, detail="pipeline not ready")
    if not req.text:
        raise HTTPException(status_code=400, detail="text is required")

    result = pipeline.scan(req.text, session_id=req.session_id)

    return ScanResponse(
        is_malicious=result.is_malicious,
        risk_level=result.risk_level.value,
        final_label=result.final_label.value,
        confidence=result.confidence,
        latency_ms=result.latency_ms,
        triggered_layers=[r.layer for r in result.layers if r.triggered],
    )


@app.post("/scan/batch")
async def scan_batch(reqs: list[ScanRequest]):
    if not pipeline:
        raise HTTPException(status_code=503, detail="pipeline not ready")
    results = []
    for req in reqs:
        if not req.text:
            continue
        r = pipeline.scan(req.text, session_id=req.session_id)
        results.append(ScanResponse(
            is_malicious=r.is_malicious,
            risk_level=r.risk_level.value,
            final_label=r.final_label.value,
            confidence=r.confidence,
            latency_ms=r.latency_ms,
            triggered_layers=[layer.layer for layer in r.layers if layer.triggered],
        ))
    return results


@app.get("/health")
async def health():
    return {"status": "ok", "pipeline_loaded": pipeline is not None}
