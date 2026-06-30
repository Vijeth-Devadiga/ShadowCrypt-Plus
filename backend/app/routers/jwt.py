"""ShadowCrypt++ — JWT Router"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.models import (
    JWTDecodeRequest,
    JWTDecodeResponse,
    JWTGenerateRequest,
    JWTGenerateResponse,
    JWTVerifyRequest,
    JWTVerifyResponse,
)
from app.services import jwt_service

router = APIRouter(prefix="/api/jwt", tags=["jwt"])


@router.post("/decode", response_model=JWTDecodeResponse, summary="Decode JWT (no signature check)")
async def jwt_decode(req: JWTDecodeRequest) -> JWTDecodeResponse:
    decoded = jwt_service.decode(req.token)
    payload = decoded["payload"]
    return JWTDecodeResponse(
        header     = decoded["header"],
        payload    = payload,
        signature  = decoded["signature"],
        is_expired = jwt_service.is_expired(payload),
        expires_at = jwt_service.format_expiry(payload.get("exp")),
        issued_at  = jwt_service.format_expiry(payload.get("iat")),
    )


@router.post("/generate", response_model=JWTGenerateResponse, summary="Generate a signed JWT")
async def jwt_generate(req: JWTGenerateRequest) -> JWTGenerateResponse:
    token, exp = jwt_service.generate(
        payload    = req.payload,
        secret     = req.secret,
        algorithm  = req.algorithm.value,
        expires_in = req.expires_in,
        issuer     = req.issuer,
        subject    = req.subject,
    )
    return JWTGenerateResponse(
        token            = token,
        algorithm        = req.algorithm.value,
        expires_at       = exp,
        expires_at_human = jwt_service.format_expiry(exp) or "",
    )


@router.post("/verify", response_model=JWTVerifyResponse, summary="Verify JWT signature (HMAC)")
async def jwt_verify(req: JWTVerifyRequest) -> JWTVerifyResponse:
    valid, payload, error = jwt_service.verify_signature(req.token, req.secret)
    return JWTVerifyResponse(valid=valid, payload=payload, error=error)
