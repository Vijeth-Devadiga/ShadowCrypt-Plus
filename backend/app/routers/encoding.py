"""
ShadowCrypt++ — Encoding Router
Encode, decode, detect, and batch-chain endpoints.
"""

from __future__ import annotations

import time

from fastapi import APIRouter

from app.core.models import (
    BatchRequest,
    BatchResponse,
    DetectRequest,
    DetectResponse,
    EncodeRequest,
    EncodeResponse,
)
from app.services import encoders

router = APIRouter(prefix="/api", tags=["encoding"])


@router.post(
    "/encode",
    response_model=EncodeResponse,
    summary="Encode text",
    description="Encode using any of the 24 supported algorithms.",
)
async def encode(req: EncodeRequest) -> EncodeResponse:
    t0     = time.perf_counter()
    result = encoders.run(req.algorithm.value, req.text, "encode", req.key)
    return EncodeResponse(
        result             = result,
        algorithm          = req.algorithm.value,
        mode               = "encode",
        input_length       = len(req.text),
        output_length      = len(result),
        processing_time_ms = (time.perf_counter() - t0) * 1000,
    )


@router.post(
    "/decode",
    response_model=EncodeResponse,
    summary="Decode text",
    description="Decode using any of the 24 supported algorithms.",
)
async def decode(req: EncodeRequest) -> EncodeResponse:
    t0     = time.perf_counter()
    result = encoders.run(req.algorithm.value, req.text, "decode", req.key)
    return EncodeResponse(
        result             = result,
        algorithm          = req.algorithm.value,
        mode               = "decode",
        input_length       = len(req.text),
        output_length      = len(result),
        processing_time_ms = (time.perf_counter() - t0) * 1000,
    )


@router.post(
    "/detect",
    response_model=DetectResponse,
    summary="Auto-detect encoding format",
)
async def detect(req: DetectRequest) -> DetectResponse:
    detected, confidence, alternatives = encoders.detect_encoding(req.text)
    return DetectResponse(
        detected     = detected,
        confidence   = confidence,
        alternatives = alternatives,
    )


@router.post(
    "/batch",
    response_model=BatchResponse,
    summary="Chain multiple encoding operations",
    description="Apply up to 20 encoding steps in sequence.",
)
async def batch(req: BatchRequest) -> BatchResponse:
    result  = req.text
    history = []
    for step in req.steps:
        result = encoders.run(step.algorithm, result, step.mode, step.key)
        history.append({
            "algorithm":     step.algorithm,
            "mode":          step.mode,
            "output_length": str(len(result)),
        })
    return BatchResponse(result=result, steps=history)
