"""
ShadowCrypt++ — Hashing Engine
All 12 cryptographic hash algorithms with verify and compare.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from typing import Dict, Optional


# ─────────────────────────────────────────────
# HASH METADATA
# ─────────────────────────────────────────────

HASH_META: dict[str, dict] = {
    "md5":      {"bits": 128,  "chars": 32,  "note": "Fast but not cryptographically secure"},
    "sha1":     {"bits": 160,  "chars": 40,  "note": "Deprecated for security — use SHA-256+"},
    "sha224":   {"bits": 224,  "chars": 56,  "note": "SHA-2 family, truncated variant"},
    "sha256":   {"bits": 256,  "chars": 64,  "note": "SHA-2, industry standard"},
    "sha384":   {"bits": 384,  "chars": 96,  "note": "SHA-2, high security"},
    "sha512":   {"bits": 512,  "chars": 128, "note": "SHA-2, maximum output"},
    "sha3_256": {"bits": 256,  "chars": 64,  "note": "SHA-3 (Keccak), 256-bit"},
    "sha3_512": {"bits": 512,  "chars": 128, "note": "SHA-3 (Keccak), 512-bit"},
    "blake2b":  {"bits": 512,  "chars": 128, "note": "Fast, cryptographically secure"},
    "blake2s":  {"bits": 256,  "chars": 64,  "note": "Blake2 optimised for 32-bit"},
    "ripemd160":{"bits": 160,  "chars": 40,  "note": "Used in Bitcoin address generation"},
    "crc32":    {"bits": 32,   "chars": 8,   "note": "Checksum — not a cryptographic hash"},
    "adler32":  {"bits": 32,   "chars": 8,   "note": "Fast checksum for data integrity"},
}


# ─────────────────────────────────────────────
# INDIVIDUAL HASH FUNCTIONS
# ─────────────────────────────────────────────

def _to_bytes(text: str) -> bytes:
    return text.encode("utf-8")


def hash_md5(text: str) -> str:
    return hashlib.md5(_to_bytes(text)).hexdigest()


def hash_sha1(text: str) -> str:
    return hashlib.sha1(_to_bytes(text)).hexdigest()


def hash_sha224(text: str) -> str:
    return hashlib.sha224(_to_bytes(text)).hexdigest()


def hash_sha256(text: str) -> str:
    return hashlib.sha256(_to_bytes(text)).hexdigest()


def hash_sha384(text: str) -> str:
    return hashlib.sha384(_to_bytes(text)).hexdigest()


def hash_sha512(text: str) -> str:
    return hashlib.sha512(_to_bytes(text)).hexdigest()


def hash_sha3_256(text: str) -> str:
    return hashlib.sha3_256(_to_bytes(text)).hexdigest()


def hash_sha3_512(text: str) -> str:
    return hashlib.sha3_512(_to_bytes(text)).hexdigest()


def hash_blake2b(text: str) -> str:
    return hashlib.blake2b(_to_bytes(text)).hexdigest()


def hash_blake2s(text: str) -> str:
    return hashlib.blake2s(_to_bytes(text)).hexdigest()


def hash_ripemd160(text: str) -> str:
    try:
        h = hashlib.new("ripemd160", _to_bytes(text))
        return h.hexdigest()
    except ValueError:
        # Fallback for environments with restricted OpenSSL (e.g. FIPS mode)
        return _ripemd160_fallback(text)


def hash_crc32(text: str) -> str:
    val = zlib.crc32(_to_bytes(text)) & 0xFFFFFFFF
    return format(val, "08x")


def hash_adler32(text: str) -> str:
    val = zlib.adler32(_to_bytes(text)) & 0xFFFFFFFF
    return format(val, "08x")


def _ripemd160_fallback(text: str) -> str:
    """Pure-Python RIPEMD-160 for restricted environments."""
    # Reference: https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    data = _to_bytes(text)

    def rol(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def f(j: int, x: int, y: int, z: int) -> int:
        if j < 16:  return x ^ y ^ z
        if j < 32:  return (x & y) | (~x & z)
        if j < 48:  return (x | ~y) ^ z
        if j < 64:  return (x & z) | (y & ~z)
        return x ^ (y | ~z)

    K  = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KK = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    R  = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
          7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
          3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
          1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
          4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13]
    RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
          6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
          15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
          8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
          12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11]
    S  = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
          7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
          11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
          11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
          9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6]
    SS = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
          9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
          9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
          15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
          8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11]

    msg = bytearray(data)
    l   = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", l)

    h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0

    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[i:i+64]))
        A, B, C, D, E  = h0, h1, h2, h3, h4
        AA, BB, CC, DD, EE = h0, h1, h2, h3, h4

        for j in range(80):
            jj = j // 16
            T  = (A + f(j, B, C, D) + X[R[j]] + K[jj] + rol(0, S[j])) & 0xFFFFFFFF
            T  = (rol(T, S[j]) + E) & 0xFFFFFFFF
            A, B, C, D, E = E, T, B, rol(C, 10), D
            T  = (AA + f(79-j, BB, CC, DD) + X[RR[j]] + KK[jj] + rol(0, SS[j])) & 0xFFFFFFFF
            T  = (rol(T, SS[j]) + EE) & 0xFFFFFFFF
            AA, BB, CC, DD, EE = EE, T, BB, rol(CC, 10), DD

        T  = (h1 + C + DD) & 0xFFFFFFFF
        h1 = (h2 + D + EE) & 0xFFFFFFFF
        h2 = (h3 + E + AA) & 0xFFFFFFFF
        h3 = (h4 + A + BB) & 0xFFFFFFFF
        h4 = (h0 + B + CC) & 0xFFFFFFFF
        h0 = T

    digest = struct.pack("<5I", h0, h1, h2, h3, h4)
    return digest.hex()


# ─────────────────────────────────────────────
# DISPATCH TABLE
# ─────────────────────────────────────────────

_HASHERS: dict[str, callable] = {
    "md5":       hash_md5,
    "sha1":      hash_sha1,
    "sha224":    hash_sha224,
    "sha256":    hash_sha256,
    "sha384":    hash_sha384,
    "sha512":    hash_sha512,
    "sha3_256":  hash_sha3_256,
    "sha3_512":  hash_sha3_512,
    "blake2b":   hash_blake2b,
    "blake2s":   hash_blake2s,
    "ripemd160": hash_ripemd160,
    "crc32":     hash_crc32,
    "adler32":   hash_adler32,
}


def compute(algorithm: str, text: str) -> str:
    algo = algorithm.lower().replace("-", "_")
    fn   = _HASHERS.get(algo)
    if fn is None:
        raise ValueError(f"Unknown hash algorithm: {algorithm!r}")
    return fn(text)


def compute_all(text: str) -> Dict[str, str]:
    return {algo: fn(text) for algo, fn in _HASHERS.items()}


def verify(algorithm: str, text: str, expected_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    import hmac
    computed = compute(algorithm, text)
    return hmac.compare_digest(computed.lower(), expected_hash.lower())


def get_meta(algorithm: str) -> dict:
    return HASH_META.get(algorithm.lower(), {"bits": 0, "chars": 0, "note": ""})


def list_algorithms() -> list[str]:
    return sorted(_HASHERS.keys())
