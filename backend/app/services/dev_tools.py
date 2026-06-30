"""
ShadowCrypt++ — Developer Utilities
UUID, password, random string, timestamp, color, and slug tools.
"""

from __future__ import annotations

import math
import re
import secrets
import string
import time
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple


# ─────────────────────────────────────────────
# UUID GENERATOR
# ─────────────────────────────────────────────

def generate_uuid_v1() -> str:
    return str(uuid.uuid1())


def generate_uuid_v4() -> str:
    return str(uuid.uuid4())


def generate_uuid_v7() -> str:
    """UUID v7 — time-ordered, sortable (RFC draft)."""
    ts_ms   = int(time.time() * 1000)
    ts_hex  = format(ts_ms, "012x")
    rand    = secrets.token_hex(10)
    raw     = ts_hex + rand
    return (
        f"{raw[0:8]}-{raw[8:12]}-7{raw[13:16]}"
        f"-{format((int(raw[16:18], 16) & 0x3F | 0x80), '02x')}{raw[18:20]}"
        f"-{raw[20:32]}"
    )


_NANOID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"


def generate_nanoid(size: int = 21) -> str:
    return "".join(secrets.choice(_NANOID_ALPHABET) for _ in range(size))


def generate_uuids(version: str, count: int, nanoid_size: int = 21) -> List[str]:
    generators = {
        "v1":     generate_uuid_v1,
        "v4":     generate_uuid_v4,
        "v7":     generate_uuid_v7,
        "nanoid": lambda: generate_nanoid(nanoid_size),
    }
    fn = generators.get(version.lower())
    if fn is None:
        raise ValueError(f"Unknown UUID version: {version!r}")
    return [fn() for _ in range(count)]


# ─────────────────────────────────────────────
# PASSWORD GENERATOR
# ─────────────────────────────────────────────

_AMBIGUOUS = set("0O1lI")


def _build_charset(
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
    exclude_ambiguous: bool,
) -> str:
    charset = ""
    if uppercase: charset += string.ascii_uppercase
    if lowercase: charset += string.ascii_lowercase
    if numbers:   charset += string.digits
    if symbols:   charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if exclude_ambiguous:
        charset = "".join(ch for ch in charset if ch not in _AMBIGUOUS)
    return charset


def password_strength(
    length: int,
    charset_size: int,
) -> Tuple[str, float]:
    """Returns (label, entropy_bits)."""
    entropy = length * math.log2(charset_size) if charset_size > 0 else 0
    if entropy < 28:
        label = "Very Weak"
    elif entropy < 36:
        label = "Weak"
    elif entropy < 60:
        label = "Fair"
    elif entropy < 80:
        label = "Good"
    elif entropy < 100:
        label = "Strong"
    elif entropy < 128:
        label = "Very Strong"
    else:
        label = "Excellent"
    return label, round(entropy, 1)


def generate_passwords(
    length: int,
    uppercase: bool = True,
    lowercase: bool = True,
    numbers: bool = True,
    symbols: bool = True,
    count: int = 1,
    exclude_ambiguous: bool = False,
) -> Tuple[List[str], str, float]:
    charset = _build_charset(uppercase, lowercase, numbers, symbols, exclude_ambiguous)
    if not charset:
        raise ValueError("At least one character set must be selected")

    passwords = [
        "".join(secrets.choice(charset) for _ in range(length))
        for _ in range(count)
    ]
    strength, entropy = password_strength(length, len(charset))
    return passwords, strength, entropy


# ─────────────────────────────────────────────
# RANDOM STRING GENERATOR
# ─────────────────────────────────────────────

_CHARSETS: dict[str, str] = {
    "alphanumeric": string.ascii_letters + string.digits,
    "hex":          "0123456789abcdef",
    "base64":       string.ascii_letters + string.digits + "+/",
    "numeric":      string.digits,
    "alpha":        string.ascii_letters,
    "symbols":      string.punctuation,
}


def generate_random_strings(
    length: int,
    string_type: str = "alphanumeric",
    count: int = 1,
) -> List[str]:
    charset = _CHARSETS.get(string_type.lower())
    if not charset:
        raise ValueError(f"Unknown string type: {string_type!r}")
    return [
        "".join(secrets.choice(charset) for _ in range(length))
        for _ in range(count)
    ]


# ─────────────────────────────────────────────
# TIMESTAMP CONVERTER
# ─────────────────────────────────────────────

def _time_ago(unix_ts: int) -> str:
    diff = int(time.time()) - unix_ts
    abs_diff = abs(diff)
    suffix = "ago" if diff >= 0 else "from now"

    if abs_diff < 60:
        return f"{abs_diff}s {suffix}"
    if abs_diff < 3600:
        return f"{abs_diff // 60}m {abs_diff % 60}s {suffix}"
    if abs_diff < 86400:
        h = abs_diff // 3600
        m = (abs_diff % 3600) // 60
        return f"{h}h {m}m {suffix}"
    d = abs_diff // 86400
    return f"{d}d {suffix}"


def convert_timestamp(unix: Optional[int] = None, date_string: Optional[str] = None) -> dict:
    if unix is not None:
        ts = unix
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    else:
        dt = datetime.fromisoformat(date_string.replace("Z", "+00:00"))
        ts = int(dt.timestamp())

    return {
        "unix":     ts,
        "iso":      dt.isoformat(),
        "utc":      dt.strftime("%a, %d %b %Y %H:%M:%S GMT"),
        "local":    dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "relative": _time_ago(ts),
    }


# ─────────────────────────────────────────────
# COLOR CONVERTER
# ─────────────────────────────────────────────

def _hex_to_rgb(hex_str: str) -> Tuple[int, int, int]:
    hex_str = hex_str.lstrip("#")
    if len(hex_str) == 3:
        hex_str = "".join(c * 2 for c in hex_str)
    r, g, b = (int(hex_str[i:i+2], 16) for i in (0, 2, 4))
    return r, g, b


def _rgb_to_hsl(r: int, g: int, b: int) -> Tuple[float, float, float]:
    r_, g_, b_ = r / 255, g / 255, b / 255
    cmax = max(r_, g_, b_)
    cmin = min(r_, g_, b_)
    delta = cmax - cmin
    l = (cmax + cmin) / 2

    if delta == 0:
        h = s = 0.0
    else:
        s = delta / (1 - abs(2 * l - 1))
        if cmax == r_:
            h = 60 * (((g_ - b_) / delta) % 6)
        elif cmax == g_:
            h = 60 * ((b_ - r_) / delta + 2)
        else:
            h = 60 * ((r_ - g_) / delta + 4)

    return round(h, 1), round(s * 100, 1), round(l * 100, 1)


def convert_color(value: str) -> dict:
    value = value.strip()
    r = g = b = 0
    a = 1.0

    if re.match(r"^#[0-9A-Fa-f]{3,6}$", value):
        r, g, b = _hex_to_rgb(value)
    elif re.match(r"^rgba?\(", value):
        nums = re.findall(r"[\d.]+", value)
        r, g, b = int(nums[0]), int(nums[1]), int(nums[2])
        if len(nums) > 3:
            a = float(nums[3])
    elif re.match(r"^hsla?\(", value):
        nums = re.findall(r"[\d.]+", value)
        h, s, l = float(nums[0]), float(nums[1]), float(nums[2])
        if len(nums) > 3:
            a = float(nums[3])
        # Convert HSL to RGB
        s_, l_ = s / 100, l / 100
        c  = (1 - abs(2 * l_ - 1)) * s_
        x  = c * (1 - abs((h / 60) % 2 - 1))
        m  = l_ - c / 2
        if h < 60:   r_, g_, b_ = c, x, 0
        elif h < 120: r_, g_, b_ = x, c, 0
        elif h < 180: r_, g_, b_ = 0, c, x
        elif h < 240: r_, g_, b_ = 0, x, c
        elif h < 300: r_, g_, b_ = x, 0, c
        else:         r_, g_, b_ = c, 0, x
        r, g, b = int((r_ + m) * 255), int((g_ + m) * 255), int((b_ + m) * 255)
    else:
        raise ValueError(f"Unrecognised color format: {value!r}")

    hex_val     = f"#{r:02x}{g:02x}{b:02x}"
    h_val, s_val, l_val = _rgb_to_hsl(r, g, b)

    return {
        "hex":  hex_val.upper(),
        "rgb":  {"r": r, "g": g, "b": b},
        "hsl":  {"h": h_val, "s": s_val, "l": l_val},
        "rgba": f"rgba({r},{g},{b},{a})",
        "hsla": f"hsla({h_val},{s_val}%,{l_val}%,{a})",
    }


# ─────────────────────────────────────────────
# SLUG / STRING TRANSFORMS
# ─────────────────────────────────────────────

def _to_words(text: str) -> List[str]:
    text = re.sub(r"[^a-zA-Z0-9\s]", " ", text)
    return [w for w in re.split(r"[\s_\-]+", text) if w]


def generate_slug_variants(text: str) -> dict:
    words = _to_words(text)
    lower = [w.lower() for w in words]
    upper = [w.upper() for w in words]

    return {
        "slug":        "-".join(lower),
        "snake_case":  "_".join(lower),
        "camel_case":  lower[0] + "".join(w.title() for w in lower[1:]) if lower else "",
        "pascal_case": "".join(w.title() for w in lower),
        "kebab_case":  "-".join(lower),
        "upper":       " ".join(upper),
        "lower":       " ".join(lower),
    }
