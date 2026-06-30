"""
ShadowCrypt++ — Pydantic Schemas
All request / response models with strict validation.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.config import get_settings

_cfg = get_settings()
_MAX = _cfg.max_text_bytes


def _size_check(v: str) -> str:
    if len(v.encode()) > _MAX:
        raise ValueError(f"Input exceeds {_MAX // 1_048_576} MB limit")
    return v


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class EncodingAlgo(str, Enum):
    BASE64    = "base64"
    BASE32    = "base32"
    BASE16    = "base16"
    BASE58    = "base58"
    BASE62    = "base62"
    BASE85    = "base85"
    HEX       = "hex"
    BINARY    = "binary"
    OCTAL     = "octal"
    DECIMAL   = "decimal"
    URL       = "url"
    HTML      = "html"
    UNICODE   = "unicode"
    ASCII_    = "ascii"
    PUNYCODE  = "punycode"
    ROT13     = "rot13"
    CAESAR    = "caesar"
    VIGENERE  = "vigenere"
    ATBASH    = "atbash"
    MORSE     = "morse"
    BACON     = "bacon"
    RAILFENCE = "railfence"
    AFFINE    = "affine"
    POLYBIUS  = "polybius"


class HashAlgo(str, Enum):
    MD5       = "md5"
    SHA1      = "sha1"
    SHA224    = "sha224"
    SHA256    = "sha256"
    SHA384    = "sha384"
    SHA512    = "sha512"
    SHA3_256  = "sha3_256"
    SHA3_512  = "sha3_512"
    BLAKE2B   = "blake2b"
    BLAKE2S   = "blake2s"
    RIPEMD160 = "ripemd160"
    CRC32     = "crc32"
    ADLER32   = "adler32"


class JWTAlgo(str, Enum):
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"


class CompressionAlgo(str, Enum):
    GZIP   = "gzip"
    ZLIB   = "zlib"
    LZMA   = "lzma"
    BROTLI = "brotli"


class UUIDVersion(str, Enum):
    V1     = "v1"
    V4     = "v4"
    V7     = "v7"
    NANOID = "nanoid"


class StringType(str, Enum):
    ALPHANUMERIC = "alphanumeric"
    HEX          = "hex"
    BASE64       = "base64"
    NUMERIC      = "numeric"
    ALPHA        = "alpha"
    SYMBOLS      = "symbols"


# ─────────────────────────────────────────────
# ENCODING
# ─────────────────────────────────────────────

class EncodeRequest(BaseModel):
    text:      str           = Field(..., min_length=1)
    algorithm: EncodingAlgo  = EncodingAlgo.BASE64
    key:       Optional[str] = Field(None, max_length=1024)

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class EncodeResponse(BaseModel):
    result:             str
    algorithm:          str
    mode:               str
    input_length:       int
    output_length:      int
    processing_time_ms: float


class DetectRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100_000)


class DetectResponse(BaseModel):
    detected:     Optional[str]
    confidence:   float
    alternatives: List[str]


class BatchStep(BaseModel):
    algorithm: str
    mode:      str = Field("encode", pattern="^(encode|decode)$")
    key:       Optional[str] = None


class BatchRequest(BaseModel):
    text:  str             = Field(..., min_length=1)
    steps: List[BatchStep] = Field(..., min_length=1, max_length=20)

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class BatchResponse(BaseModel):
    result: str
    steps:  List[Dict[str, str]]


# ─────────────────────────────────────────────
# HASHING
# ─────────────────────────────────────────────

class HashRequest(BaseModel):
    text:      str      = Field(..., min_length=1)
    algorithm: HashAlgo = HashAlgo.SHA256

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class HashResponse(BaseModel):
    hash:      str
    algorithm: str
    length:    int
    bits:      int


class HashAllRequest(BaseModel):
    text: str = Field(..., min_length=1)

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class HashAllResponse(BaseModel):
    hashes:       Dict[str, str]
    input_length: int


class HashVerifyRequest(BaseModel):
    text:      str      = Field(..., min_length=1)
    hash:      str      = Field(..., min_length=4, max_length=512)
    algorithm: HashAlgo = HashAlgo.SHA256

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class HashVerifyResponse(BaseModel):
    match:     bool
    algorithm: str
    computed:  str


# ─────────────────────────────────────────────
# JWT
# ─────────────────────────────────────────────

class JWTDecodeRequest(BaseModel):
    token: str = Field(..., min_length=10, max_length=32_768)


class JWTDecodeResponse(BaseModel):
    header:     Dict[str, Any]
    payload:    Dict[str, Any]
    signature:  str
    is_expired: bool
    expires_at: Optional[str]
    issued_at:  Optional[str]


class JWTGenerateRequest(BaseModel):
    payload:    Dict[str, Any] = Field(default_factory=dict)
    secret:     str            = Field(..., min_length=1, max_length=4096)
    algorithm:  JWTAlgo        = JWTAlgo.HS256
    expires_in: int            = Field(3600, ge=1, le=31_536_000)
    issuer:     Optional[str]  = Field(None, max_length=256)
    subject:    Optional[str]  = Field(None, max_length=256)

    @field_validator("payload")
    @classmethod
    def no_reserved_claims(cls, v: dict) -> dict:
        reserved = {"iat", "exp", "iss", "sub"}
        overlap  = reserved & set(v.keys())
        if overlap:
            raise ValueError(f"Reserved claims {overlap} must use dedicated fields")
        return v


class JWTGenerateResponse(BaseModel):
    token:            str
    algorithm:        str
    expires_at:       int
    expires_at_human: str


class JWTVerifyRequest(BaseModel):
    token:  str = Field(..., min_length=10, max_length=32_768)
    secret: str = Field(..., min_length=1, max_length=4096)


class JWTVerifyResponse(BaseModel):
    valid:   bool
    payload: Optional[Dict[str, Any]]
    error:   Optional[str]


# ─────────────────────────────────────────────
# COMPRESSION
# ─────────────────────────────────────────────

class CompressRequest(BaseModel):
    text:          str              = Field(..., min_length=1)
    algorithm:     CompressionAlgo  = CompressionAlgo.GZIP
    base64_output: bool             = True

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class CompressResponse(BaseModel):
    result:          str
    algorithm:       str
    original_size:   int
    compressed_size: int
    ratio:           float
    base64_encoded:  bool


class DecompressRequest(BaseModel):
    text:         str             = Field(..., min_length=1)
    algorithm:    CompressionAlgo = CompressionAlgo.GZIP
    base64_input: bool            = True

    @field_validator("text")
    @classmethod
    def check_size(cls, v: str) -> str:
        return _size_check(v)


class DecompressResponse(BaseModel):
    result:            str
    algorithm:         str
    compressed_size:   int
    decompressed_size: int


# ─────────────────────────────────────────────
# DEV TOOLS
# ─────────────────────────────────────────────

class UUIDRequest(BaseModel):
    version:     UUIDVersion = UUIDVersion.V4
    count:       int         = Field(1, ge=1, le=100)
    nanoid_size: int         = Field(21, ge=4, le=128)


class UUIDResponse(BaseModel):
    uuids:   List[str]
    version: str
    count:   int


class PasswordRequest(BaseModel):
    length:            int  = Field(20, ge=8, le=256)
    uppercase:         bool = True
    lowercase:         bool = True
    numbers:           bool = True
    symbols:           bool = True
    count:             int  = Field(1, ge=1, le=50)
    exclude_ambiguous: bool = False


class PasswordResponse(BaseModel):
    passwords:    List[str]
    strength:     str
    entropy_bits: float
    length:       int


class RandomStringRequest(BaseModel):
    length:      int        = Field(32, ge=1, le=1024)
    string_type: StringType = StringType.ALPHANUMERIC
    count:       int        = Field(1, ge=1, le=50)


class RandomStringResponse(BaseModel):
    strings: List[str]
    type:    str
    length:  int


class TimestampRequest(BaseModel):
    unix:        Optional[int] = None
    date_string: Optional[str] = None

    @model_validator(mode="after")
    def require_one(self) -> "TimestampRequest":
        if self.unix is None and self.date_string is None:
            raise ValueError("Provide either 'unix' or 'date_string'")
        return self


class TimestampResponse(BaseModel):
    unix:     int
    iso:      str
    utc:      str
    local:    str
    relative: str


class ColorRequest(BaseModel):
    value: str = Field(..., min_length=2, max_length=50)


class ColorResponse(BaseModel):
    hex:  str
    rgb:  Dict[str, int]
    hsl:  Dict[str, float]
    rgba: str
    hsla: str


class SlugRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10_000)


class SlugResponse(BaseModel):
    slug:        str
    snake_case:  str
    camel_case:  str
    pascal_case: str
    kebab_case:  str
    upper:       str
    lower:       str


# ─────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error:  str
    detail: Optional[str] = None
    code:   int
