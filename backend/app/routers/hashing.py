"""
ShadowCrypt++ — Hashing Router
Route order matters: /hash/all and /hash/verify MUST be declared
before /hash/{algorithm} to avoid FastAPI matching them as path params.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.models import (
    HashAllRequest,
    HashAllResponse,
    HashRequest,
    HashResponse,
    HashVerifyRequest,
    HashVerifyResponse,
)
from app.services import hashers

router = APIRouter(prefix="/api/hash", tags=["hashing"])


@router.post(
    "/all",
    response_model=HashAllResponse,
    summary="Generate all hashes simultaneously",
)
async def hash_all(req: HashAllRequest) -> HashAllResponse:
    return HashAllResponse(
        hashes       = hashers.compute_all(req.text),
        input_length = len(req.text),
    )


@router.post(
    "/verify",
    response_model=HashVerifyResponse,
    summary="Verify a hash (constant-time comparison)",
)
async def hash_verify(req: HashVerifyRequest) -> HashVerifyResponse:
    computed = hashers.compute(req.algorithm.value, req.text)
    match    = hashers.verify(req.algorithm.value, req.text, req.hash)
    return HashVerifyResponse(
        match     = match,
        algorithm = req.algorithm.value,
        computed  = computed,
    )


@router.post(
    "",
    response_model=HashResponse,
    summary="Generate a hash",
)
async def hash_text(req: HashRequest) -> HashResponse:
    h    = hashers.compute(req.algorithm.value, req.text)
    meta = hashers.get_meta(req.algorithm.value)
    return HashResponse(
        hash      = h,
        algorithm = req.algorithm.value,
        length    = len(h),
        bits      = meta.get("bits", 0),
    )
