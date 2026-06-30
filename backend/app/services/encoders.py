"""
ShadowCrypt++ — Encoding Engine
Complete implementation of all 24 encoding/decoding algorithms.
"""

from __future__ import annotations

import itertools

import base64
import binascii
import html as html_module
import re
import urllib.parse
from typing import Optional


# ─────────────────────────────────────────────
# BASE ENCODINGS
# ─────────────────────────────────────────────

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def decode_base64(text: str) -> str:
    text = text.strip().replace("\n", "").replace("\r", "")
    padding = 4 - len(text) % 4
    if padding != 4:
        text += "=" * padding
    return base64.b64decode(text).decode("utf-8")


def encode_base32(text: str) -> str:
    return base64.b32encode(text.encode("utf-8")).decode("ascii")


def decode_base32(text: str) -> str:
    text = text.upper().strip()
    padding = 8 - len(text) % 8
    if padding != 8:
        text += "=" * padding
    return base64.b32decode(text).decode("utf-8")


def encode_base16(text: str) -> str:
    return base64.b16encode(text.encode("utf-8")).decode("ascii")


def decode_base16(text: str) -> str:
    return base64.b16decode(text.upper().replace(" ", "")).decode("utf-8")


_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _encode_base_n(text: str, alphabet: str) -> str:
    data   = text.encode("utf-8")
    base   = len(alphabet)
    n      = int.from_bytes(data, "big")
    result = ""
    while n > 0:
        n, rem = divmod(n, base)
        result  = alphabet[rem] + result
    leading = sum(1 for b in data if b == 0)
    return alphabet[0] * leading + (result or alphabet[0])


def _decode_base_n(text: str, alphabet: str) -> str:
    base   = len(alphabet)
    n      = 0
    for ch in text.strip():
        idx = alphabet.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid character for this alphabet: {ch!r}")
        n = n * base + idx
    byte_count = (n.bit_length() + 7) // 8
    data       = n.to_bytes(max(byte_count, 1), "big")
    # Count leading zero-chars only at the START (not anywhere in string)
    stripped   = text.strip()
    leading    = len(stripped) - len(stripped.lstrip(alphabet[0]))
    return (b"\x00" * leading + data.lstrip(b"\x00")).decode("utf-8")


def encode_base58(text: str) -> str:
    return _encode_base_n(text, _B58_ALPHABET)


def decode_base58(text: str) -> str:
    return _decode_base_n(text, _B58_ALPHABET)


def encode_base62(text: str) -> str:
    return _encode_base_n(text, _B62_ALPHABET)


def decode_base62(text: str) -> str:
    return _decode_base_n(text, _B62_ALPHABET)


def encode_base85(text: str) -> str:
    return base64.b85encode(text.encode("utf-8")).decode("ascii")


def decode_base85(text: str) -> str:
    return base64.b85decode(text.strip()).decode("utf-8")


# ─────────────────────────────────────────────
# NUMERIC ENCODINGS
# ─────────────────────────────────────────────

def encode_hex(text: str) -> str:
    return text.encode("utf-8").hex()


def decode_hex(text: str) -> str:
    return bytes.fromhex(text.replace(" ", "").replace("\n", "")).decode("utf-8")


def encode_binary(text: str) -> str:
    return " ".join(format(b, "08b") for b in text.encode("utf-8"))


def decode_binary(text: str) -> str:
    groups = re.split(r"\s+", text.strip())
    return bytes(int(g, 2) for g in groups if g).decode("utf-8")


def encode_octal(text: str) -> str:
    return " ".join(format(b, "03o") for b in text.encode("utf-8"))


def decode_octal(text: str) -> str:
    groups = re.split(r"\s+", text.strip())
    return bytes(int(g, 8) for g in groups if g).decode("utf-8")


def encode_decimal(text: str) -> str:
    return " ".join(str(b) for b in text.encode("utf-8"))


def decode_decimal(text: str) -> str:
    groups = re.split(r"\s+", text.strip())
    return bytes(int(g) for g in groups if g).decode("utf-8")


# ─────────────────────────────────────────────
# WEB ENCODINGS
# ─────────────────────────────────────────────

def encode_url(text: str) -> str:
    return urllib.parse.quote(text, safe="")


def decode_url(text: str) -> str:
    return urllib.parse.unquote(text)


def encode_html(text: str) -> str:
    return html_module.escape(text, quote=True)


def decode_html(text: str) -> str:
    return html_module.unescape(text)


def encode_unicode(text: str) -> str:
    result = []
    for ch in text:
        cp = ord(ch)
        if cp > 127:
            result.append(f"\\u{cp:04x}")
        else:
            result.append(ch)
    return "".join(result)


def decode_unicode(text: str) -> str:
    return text.encode("raw_unicode_escape").decode("unicode_escape")


def encode_ascii(text: str) -> str:
    return " ".join(str(ord(ch)) for ch in text)


def decode_ascii(text: str) -> str:
    return "".join(chr(int(n)) for n in re.split(r"\s+", text.strip()) if n)


def encode_punycode(text: str) -> str:
    try:
        return text.encode("punycode").decode("ascii")
    except Exception:
        return text.encode("idna").decode("ascii")


def decode_punycode(text: str) -> str:
    try:
        return text.encode("ascii").decode("punycode")
    except Exception:
        return text


# ─────────────────────────────────────────────
# CLASSICAL CIPHERS
# ─────────────────────────────────────────────

def rot13(text: str, _key: Optional[str] = None) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + 13) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + 13) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def caesar_encode(text: str, key: Optional[str] = None) -> str:
    shift = int(key or "3") % 26
    return _caesar_shift(text, shift)


def caesar_decode(text: str, key: Optional[str] = None) -> str:
    shift = (26 - int(key or "3") % 26) % 26
    return _caesar_shift(text, shift)


def _caesar_shift(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            result.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            result.append(ch)
    return "".join(result)


def vigenere_encode(text: str, key: Optional[str] = None) -> str:
    return _vigenere(text, key or "key", decode=False)


def vigenere_decode(text: str, key: Optional[str] = None) -> str:
    return _vigenere(text, key or "key", decode=True)


def _vigenere(text: str, key: str, decode: bool) -> str:
    key   = re.sub(r"[^a-zA-Z]", "", key).lower()
    if not key:
        raise ValueError("Vigenère key must contain at least one letter")
    result = []
    ki     = 0
    for ch in text:
        if ch.isalpha():
            base  = ord("a") if ch.islower() else ord("A")
            k     = ord(key[ki % len(key)]) - ord("a")
            shift = (26 - k) % 26 if decode else k
            result.append(chr((ord(ch) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(ch)
    return "".join(result)


def atbash(text: str, _key: Optional[str] = None) -> str:
    result = []
    for ch in text:
        if "a" <= ch <= "z":
            result.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            result.append(ch)
    return "".join(result)


_MORSE_TABLE: dict[str, str] = {
    "a": ".-",   "b": "-...", "c": "-.-.", "d": "-..",  "e": ".",
    "f": "..-.", "g": "--.",  "h": "....", "i": "..",   "j": ".---",
    "k": "-.-",  "l": ".-..", "m": "--",   "n": "-.",   "o": "---",
    "p": ".--.", "q": "--.-", "r": ".-.",  "s": "...",  "t": "-",
    "u": "..-",  "v": "...-", "w": ".--",  "x": "-..-", "y": "-.--",
    "z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-...." , "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--",
    "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...",
    ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.",
    "-": "-....-", "_": "..--.-", '"': ".-..-.", "@": ".--.-.",
    "'": ".----.",
}
_MORSE_REV = {v: k for k, v in _MORSE_TABLE.items()}


def encode_morse(text: str, _key: Optional[str] = None) -> str:
    words = text.lower().split(" ")
    encoded_words = []
    for word in words:
        encoded_chars = []
        for ch in word:
            if ch in _MORSE_TABLE:
                encoded_chars.append(_MORSE_TABLE[ch])
        if encoded_chars:
            encoded_words.append(" ".join(encoded_chars))
    return " / ".join(encoded_words)


def decode_morse(text: str, _key: Optional[str] = None) -> str:
    words = text.strip().split(" / ")
    decoded_words = []
    for word in words:
        codes   = word.strip().split(" ")
        decoded = "".join(_MORSE_REV.get(c, "?") for c in codes if c)
        decoded_words.append(decoded)
    return " ".join(decoded_words)


_BACON_TABLE: dict[str, str] = {
    ch: ''.join('B' if (i >> (4 - bit)) & 1 else 'A' for bit in range(5))
    for i, ch in enumerate('abcdefghijklmnopqrstuvwxyz')
}
_BACON_REV = {v: k for k, v in _BACON_TABLE.items()}


def encode_bacon(text: str, _key: Optional[str] = None) -> str:
    return " ".join(
        _BACON_TABLE[ch]
        for ch in text.lower()
        if ch in _BACON_TABLE
    )


def decode_bacon(text: str, _key: Optional[str] = None) -> str:
    groups = re.findall(r"[AB]{5}", text.upper().replace(" ", ""))
    return "".join(_BACON_REV.get(g, "?") for g in groups)


def encode_railfence(text: str, key: Optional[str] = None) -> str:
    rails = max(2, int(key or "3"))
    fence = [[] for _ in range(rails)]
    r, dr = 0, 1
    for ch in text:
        fence[r].append(ch)
        if r == 0:
            dr = 1
        elif r == rails - 1:
            dr = -1
        r += dr
    return "".join(ch for rail in fence for ch in rail)


def decode_railfence(text: str, key: Optional[str] = None) -> str:
    rails = max(2, int(key or "3"))
    n     = len(text)
    idx   = list(range(n))
    order = []
    r, dr = 0, 1
    for i in range(n):
        order.append((r, i))
        if r == 0:
            dr = 1
        elif r == rails - 1:
            dr = -1
        r += dr
    sorted_order = sorted(range(n), key=lambda i: (order[i][0], order[i][1]))
    result       = [""] * n
    for pos, orig in enumerate(sorted_order):
        result[orig] = text[pos]
    return "".join(result)


def _mod_inverse(a: int, m: int) -> int:
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"No modular inverse exists for a={a}, gcd(a,m) ≠ 1")


def encode_affine(text: str, key: Optional[str] = None) -> str:
    a, b = _parse_affine_key(key)
    return _affine(text, a, b, decode=False)


def decode_affine(text: str, key: Optional[str] = None) -> str:
    a, b = _parse_affine_key(key)
    return _affine(text, a, b, decode=True)


def _parse_affine_key(key: Optional[str]) -> tuple[int, int]:
    if key and "," in key:
        parts = key.split(",")
        return int(parts[0].strip()), int(parts[1].strip())
    return 5, 8


def _affine(text: str, a: int, b: int, decode: bool) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("a") if ch.islower() else ord("A")
            x    = ord(ch) - base
            if decode:
                enc = (_mod_inverse(a, 26) * (x - b + 26)) % 26
            else:
                enc = (a * x + b) % 26
            result.append(chr(enc + base))
        else:
            result.append(ch)
    return "".join(result)


_POLYBIUS_SQ = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # 5×5, I=J


def encode_polybius(text: str, _key: Optional[str] = None) -> str:
    result = []
    for ch in text.upper():
        if ch == "J":
            ch = "I"
        idx = _POLYBIUS_SQ.find(ch)
        if idx >= 0:
            result.append(f"{idx // 5 + 1}{idx % 5 + 1}")
        elif ch == " ":
            result.append(" ")
    return "".join(result)


def decode_polybius(text: str, _key: Optional[str] = None) -> str:
    result = []
    for m in re.finditer(r"(\d)(\d)", text):
        r, c = int(m.group(1)) - 1, int(m.group(2)) - 1
        idx   = r * 5 + c
        if 0 <= idx < len(_POLYBIUS_SQ):
            result.append(_POLYBIUS_SQ[idx])
    return "".join(result)


# ─────────────────────────────────────────────
# FORMAT DETECTION
# ─────────────────────────────────────────────

def detect_encoding(text: str) -> tuple[Optional[str], float, list[str]]:
    """Return (best_guess, confidence, alternatives)."""
    text    = text.strip()
    matches = []

    if re.match(r"^[01\s]+$", text):
        bits = re.sub(r"\s", "", text)
        if len(bits) % 8 == 0 and len(bits) > 0:
            matches.append(("binary", 0.95))

    if re.match(r"^[0-9A-Fa-f\s]+$", text):
        h = re.sub(r"\s", "", text)
        if len(h) % 2 == 0 and len(h) > 0:
            matches.append(("hex", 0.85))

    if re.match(r"^[A-Za-z0-9+/]+=*$", text) and len(text) % 4 == 0 and len(text) > 4:
        matches.append(("base64", 0.90))

    if text.startswith("eyJ") and len(text.split(".")) == 3:
        matches.append(("jwt", 0.99))

    if re.search(r"%[0-9A-Fa-f]{2}", text):
        matches.append(("url", 0.92))

    if re.search(r"&[a-z]+;|&#\d+;", text):
        matches.append(("html", 0.90))

    if re.match(r"^[\.\-\s/]+$", text) and len(text) > 2:
        matches.append(("morse", 0.88))

    if re.search(r"\\u[0-9a-fA-F]{4}", text):
        matches.append(("unicode", 0.92))

    if re.match(r"^[A-Z2-7]+=*$", text) and len(re.sub(r"=", "", text)) % 8 in (0, 2, 4, 5, 7):
        matches.append(("base32", 0.75))

    matches.sort(key=lambda x: -x[1])

    if not matches:
        return None, 0.0, []

    best = matches[0]
    alts = [m[0] for m in matches[1:4]]
    return best[0], best[1], alts


# ─────────────────────────────────────────────
# DISPATCH TABLE
# ─────────────────────────────────────────────

_ENCODERS: dict[str, tuple] = {
    "base64":    (encode_base64,    decode_base64),
    "base32":    (encode_base32,    decode_base32),
    "base16":    (encode_base16,    decode_base16),
    "base58":    (encode_base58,    decode_base58),
    "base62":    (encode_base62,    decode_base62),
    "base85":    (encode_base85,    decode_base85),
    "hex":       (encode_hex,       decode_hex),
    "binary":    (encode_binary,    decode_binary),
    "octal":     (encode_octal,     decode_octal),
    "decimal":   (encode_decimal,   decode_decimal),
    "url":       (encode_url,       decode_url),
    "html":      (encode_html,      decode_html),
    "unicode":   (encode_unicode,   decode_unicode),
    "ascii":     (encode_ascii,     decode_ascii),
    "punycode":  (encode_punycode,  decode_punycode),
    "rot13":     (rot13,            rot13),
    "caesar":    (caesar_encode,    caesar_decode),
    "vigenere":  (vigenere_encode,  vigenere_decode),
    "atbash":    (atbash,           atbash),
    "morse":     (encode_morse,     decode_morse),
    "bacon":     (encode_bacon,     decode_bacon),
    "railfence": (encode_railfence, decode_railfence),
    "affine":    (encode_affine,    decode_affine),
    "polybius":  (encode_polybius,  decode_polybius),
}


def run(algorithm: str, text: str, mode: str, key: Optional[str] = None) -> str:
    """Dispatch encode/decode for the given algorithm."""
    algo = algorithm.lower()
    if algo not in _ENCODERS:
        raise ValueError(f"Unknown algorithm: {algorithm!r}")
    encoder, decoder = _ENCODERS[algo]
    fn = encoder if mode == "encode" else decoder
    try:
        import inspect
        sig = inspect.signature(fn)
        if len(sig.parameters) >= 2:
            return fn(text, key)
        return fn(text)
    except (UnicodeDecodeError, binascii.Error, ValueError) as exc:
        raise ValueError(f"Decoding failed: {exc}") from exc


def list_algorithms() -> list[str]:
    return sorted(_ENCODERS.keys())
