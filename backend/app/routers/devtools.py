"""ShadowCrypt++ — Developer Utilities Router"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.models import (
    ColorRequest,
    ColorResponse,
    PasswordRequest,
    PasswordResponse,
    RandomStringRequest,
    RandomStringResponse,
    SlugRequest,
    SlugResponse,
    TimestampRequest,
    TimestampResponse,
    UUIDRequest,
    UUIDResponse,
)
from app.services import dev_tools

router = APIRouter(prefix="/api", tags=["dev-tools"])


@router.post("/uuid", response_model=UUIDResponse, summary="Generate UUIDs or NanoIDs")
async def generate_uuid(req: UUIDRequest) -> UUIDResponse:
    ids = dev_tools.generate_uuids(req.version.value, req.count, req.nanoid_size)
    return UUIDResponse(uuids=ids, version=req.version.value, count=len(ids))


@router.post("/password", response_model=PasswordResponse, summary="Generate secure passwords")
async def generate_password(req: PasswordRequest) -> PasswordResponse:
    passwords, strength, entropy = dev_tools.generate_passwords(
        length            = req.length,
        uppercase         = req.uppercase,
        lowercase         = req.lowercase,
        numbers           = req.numbers,
        symbols           = req.symbols,
        count             = req.count,
        exclude_ambiguous = req.exclude_ambiguous,
    )
    return PasswordResponse(
        passwords    = passwords,
        strength     = strength,
        entropy_bits = entropy,
        length       = req.length,
    )


@router.post("/random-string", response_model=RandomStringResponse, summary="Generate random strings")
async def generate_random_string(req: RandomStringRequest) -> RandomStringResponse:
    strings = dev_tools.generate_random_strings(req.length, req.string_type.value, req.count)
    return RandomStringResponse(strings=strings, type=req.string_type.value, length=req.length)


@router.post("/timestamp", response_model=TimestampResponse, summary="Convert timestamps")
async def convert_timestamp(req: TimestampRequest) -> TimestampResponse:
    result = dev_tools.convert_timestamp(req.unix, req.date_string)
    return TimestampResponse(**result)


@router.post("/color", response_model=ColorResponse, summary="Convert color formats")
async def convert_color(req: ColorRequest) -> ColorResponse:
    result = dev_tools.convert_color(req.value)
    return ColorResponse(**result)


@router.post("/slug", response_model=SlugResponse, summary="Generate slug and string variants")
async def generate_slug(req: SlugRequest) -> SlugResponse:
    result = dev_tools.generate_slug_variants(req.text)
    return SlugResponse(**result)
