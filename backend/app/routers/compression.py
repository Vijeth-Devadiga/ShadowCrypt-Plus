"""ShadowCrypt++ — Compression Router"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.models import (
    CompressRequest,
    CompressResponse,
    DecompressRequest,
    DecompressResponse,
)
from app.services import compressors

router = APIRouter(prefix="/api", tags=["compression"])


@router.post("/compress", response_model=CompressResponse, summary="Compress text")
async def compress(req: CompressRequest) -> CompressResponse:
    result, orig, comp = compressors.compress(req.text, req.algorithm.value, req.base64_output)
    return CompressResponse(
        result          = result,
        algorithm       = req.algorithm.value,
        original_size   = orig,
        compressed_size = comp,
        ratio           = round((1 - comp / max(orig, 1)) * 100, 1),
        base64_encoded  = req.base64_output,
    )


@router.post("/decompress", response_model=DecompressResponse, summary="Decompress data")
async def decompress(req: DecompressRequest) -> DecompressResponse:
    result, comp, decomp = compressors.decompress(req.text, req.algorithm.value, req.base64_input)
    return DecompressResponse(
        result            = result,
        algorithm         = req.algorithm.value,
        compressed_size   = comp,
        decompressed_size = decomp,
    )
