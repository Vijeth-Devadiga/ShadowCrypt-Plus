"""
ShadowCrypt++ — Compression Engine
GZIP, ZLIB, Brotli, and LZMA compress/decompress.
"""

from __future__ import annotations

import base64
import gzip
import lzma
import zlib
from typing import Optional


# ─────────────────────────────────────────────
# COMPRESSION FUNCTIONS
# ─────────────────────────────────────────────

def compress_gzip(data: bytes, level: int = 9) -> bytes:
    return gzip.compress(data, compresslevel=level)


def decompress_gzip(data: bytes) -> bytes:
    return gzip.decompress(data)


def compress_zlib(data: bytes, level: int = 9) -> bytes:
    return zlib.compress(data, level)


def decompress_zlib(data: bytes) -> bytes:
    return zlib.decompress(data)


def compress_lzma(data: bytes) -> bytes:
    return lzma.compress(data, preset=9)


def decompress_lzma(data: bytes) -> bytes:
    return lzma.decompress(data)


def compress_brotli(data: bytes) -> bytes:
    try:
        import brotli
        return brotli.compress(data, quality=11)
    except ImportError:
        raise ValueError("Brotli is not installed. Install with: pip install brotli")


def decompress_brotli(data: bytes) -> bytes:
    try:
        import brotli
        return brotli.decompress(data)
    except ImportError:
        raise ValueError("Brotli is not installed. Install with: pip install brotli")


# ─────────────────────────────────────────────
# DISPATCH TABLE
# ─────────────────────────────────────────────

_COMPRESSORS: dict[str, tuple] = {
    "gzip":   (compress_gzip,   decompress_gzip),
    "zlib":   (compress_zlib,   decompress_zlib),
    "lzma":   (compress_lzma,   decompress_lzma),
    "brotli": (compress_brotli, decompress_brotli),
}


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

def compress(
    text: str,
    algorithm: str = "gzip",
    base64_output: bool = True,
) -> tuple[str, int, int]:
    """
    Compress text.

    Returns (result_string, original_byte_size, compressed_byte_size).
    """
    algo = algorithm.lower()
    if algo not in _COMPRESSORS:
        raise ValueError(f"Unknown compression algorithm: {algorithm!r}")

    raw        = text.encode("utf-8")
    compress_fn, _ = _COMPRESSORS[algo]
    compressed = compress_fn(raw)

    if base64_output:
        result = base64.b64encode(compressed).decode("ascii")
    else:
        # Return raw bytes as latin-1 string for JSON transport
        result = compressed.decode("latin-1")

    return result, len(raw), len(compressed)


def decompress(
    text: str,
    algorithm: str = "gzip",
    base64_input: bool = True,
) -> tuple[str, int, int]:
    """
    Decompress data.

    Returns (decompressed_text, compressed_byte_size, decompressed_byte_size).
    """
    algo = algorithm.lower()
    if algo not in _COMPRESSORS:
        raise ValueError(f"Unknown compression algorithm: {algorithm!r}")

    if base64_input:
        compressed = base64.b64decode(text.replace("\n", "").replace("\r", ""))
    else:
        compressed = text.encode("latin-1")

    _, decompress_fn = _COMPRESSORS[algo]

    try:
        raw = decompress_fn(compressed)
    except Exception as exc:
        raise ValueError(f"Decompression failed: {exc}") from exc

    return raw.decode("utf-8"), len(compressed), len(raw)


def list_algorithms() -> list[str]:
    return sorted(_COMPRESSORS.keys())
