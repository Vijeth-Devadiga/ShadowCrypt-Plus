"""
ShadowCrypt++ — JWT Engine
Generate, decode, and verify JSON Web Tokens (HS256 / HS384 / HS512).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple


# ─────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _sign(signing_input: str, secret: str, algorithm: str) -> str:
    algo_map = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    hash_fn = algo_map.get(algorithm)
    if hash_fn is None:
        raise ValueError(f"Unsupported algorithm: {algorithm!r}")
    sig = hmac.new(
        secret.encode("utf-8"),
        signing_input.encode("utf-8"),
        hash_fn,
    ).digest()
    return _b64url_encode(sig)


# ─────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────

def generate(
    payload: Dict[str, Any],
    secret: str,
    algorithm: str = "HS256",
    expires_in: int = 3600,
    issuer: Optional[str] = None,
    subject: Optional[str] = None,
) -> Tuple[str, int]:
    """
    Generate a signed JWT.

    Returns (token_string, expiry_unix_timestamp).
    """
    now = int(time.time())
    full_payload: Dict[str, Any] = {
        "iat": now,
        "exp": now + expires_in,
        **payload,
    }
    if issuer:
        full_payload["iss"] = issuer
    if subject:
        full_payload["sub"] = subject

    header        = {"alg": algorithm, "typ": "JWT"}
    header_b64    = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64   = _b64url_encode(json.dumps(full_payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"
    signature     = _sign(signing_input, secret, algorithm)

    return f"{signing_input}.{signature}", full_payload["exp"]


def decode(token: str) -> Dict[str, Any]:
    """
    Decode a JWT without verifying the signature.
    Returns {"header": ..., "payload": ..., "signature": ...}.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT: must have exactly 3 parts separated by '.'")

    try:
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception as exc:
        raise ValueError(f"Malformed JWT: {exc}") from exc

    return {
        "header":    header,
        "payload":   payload,
        "signature": parts[2],
        "raw_parts": parts,
    }


def verify_signature(token: str, secret: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Verify the JWT signature.

    Returns (is_valid, payload_if_valid, error_message_if_invalid).
    """
    try:
        decoded = decode(token)
    except ValueError as exc:
        return False, None, str(exc)

    algorithm = decoded["header"].get("alg", "HS256")
    raw_parts = decoded["raw_parts"]

    signing_input  = f"{raw_parts[0]}.{raw_parts[1]}"
    expected_sig   = _sign(signing_input, secret, algorithm)

    if hmac.compare_digest(expected_sig, raw_parts[2]):
        return True, decoded["payload"], None
    return False, None, "Signature verification failed"


def format_expiry(exp: Optional[int]) -> Optional[str]:
    if exp is None:
        return None
    return datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()


def is_expired(payload: Dict[str, Any]) -> bool:
    exp = payload.get("exp")
    if exp is None:
        return False
    return int(time.time()) > exp
