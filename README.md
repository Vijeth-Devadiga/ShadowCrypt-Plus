# ShadowCrypt++ v2.0

> Universal Encoding Platform — Production-Ready Full-Stack Build

**30-point deep audit performed and resolved before this release.**

---

## Project Structure

```
shadowcrypt/
├── README.md
├── frontend/
│   └── index.html              Single-file SPA — open in any browser
│   └── assets/
│     └── css/ 
│     └── js/       
└── backend/
    ├── start.sh                One-command startup
    ├── requirements.txt
    ├── Dockerfile
    ├── .env.example
    ├── .gitignore
    └── app/
        ├── main.py             FastAPI entry point — routes, middleware, lifespan
        ├── __init__.py
        ├── core/
        │   ├── config.py       Pydantic-Settings — all config from .env
        │   ├── middleware.py   asyncio-safe rate limiter + security headers
        │   └── models.py       Pydantic v2 — all request/response schemas
        ├── routers/
        │   ├── encoding.py     /api/encode /api/decode /api/detect /api/batch
        │   ├── hashing.py      /api/hash  /api/hash/all  /api/hash/verify
        │   ├── jwt.py          /api/jwt/decode  /generate  /verify
        │   ├── compression.py  /api/compress  /decompress
        │   └── devtools.py     /api/uuid /password /random-string /timestamp /color /slug
        └── services/
            ├── encoders.py     24 algorithms — all roundtrip-verified
            ├── hashers.py      13 hash functions + pure-Python RIPEMD-160 fallback
            ├── jwt_service.py  HS256/384/512 generate, decode, verify
            ├── compressors.py  GZIP, ZLIB, LZMA, Brotli
            └── dev_tools.py    UUID v1/v4/v7, NanoID, password, color, slug
```

---

## Quick Start

### Backend

```bash
cd shadowcrypt/backend
chmod +x start.sh
./start.sh
```

**Or manually:**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- Swagger UI:  http://localhost:8000/docs
- ReDoc:       http://localhost:8000/redoc
- Health:      http://localhost:8000/health

### Docker

```bash
cd shadowcrypt/backend
docker build -t shadowcrypt-api .
docker run -p 8000:8000 shadowcrypt-api
```

### Frontend

Open `frontend/index.html` directly in any browser.

The nav bar shows a live **API Online / Offline** indicator. All tools work offline via the built-in client-side engine — only Compression requires the backend.

---

## What Was Fixed (30-Point Audit)

| # | Issue | Fix |
|---|-------|-----|
| 1 | `compareHashes()` double-ternary returned wrong result | Rewrote with single conditional |
| 2 | `updateStrength()` — `'veakweak'` key typo, pct map broken | Fixed key names |
| 3 | Tab system used fragile `onclick`-string parsing | Replaced with `data-tab` / `data-tab-group` attributes |
| 4 | JWT verify had no offline fallback | Added client-side HMAC verify via CryptoJS |
| 5 | Route conflict: `/api/hash/all` vs `/api/hash/{algorithm}` | Moved `all` and `verify` routes BEFORE `/{algorithm}` |
| 6 | Shortcut routes used `req.algorithm = algorithm` (type hack) | Removed — clean separate routers |
| 7 | Rate limiter had no `asyncio.Lock` — race condition | Added `asyncio.Lock` in `RateLimiter.check()` |
| 8 | Base58/Base62 leading-zero bug — counted ALL alphabet[0] chars | Fixed to count only leading chars with `lstrip()` |
| 9 | Bacon cipher — `y` and `z` shared same codes as `i` and `j` | Replaced with binary bijective 26-letter encoding |
| 10 | 159 inline styles in HTML | Replaced with semantic CSS classes |
| 11 | No loading states on API calls | Added spinner component, button disabled state |
| 12 | Hash buttons missing `aria-pressed` | Added `aria-pressed` + `aria-checked` |
| 13 | Tab buttons missing `role=tab` and `aria-selected` | Added correct ARIA attributes |
| 14 | No skip-to-content link | Added `<a class="skip-link" href="#main-content">` |
| 15 | Compression: no offline notice until user clicks | Added `offline-banner` visible when API down |
| 16 | Background animation runs when tab is hidden | Added `prefers-reduced-motion` media query |
| 17 | QR download using `<a href=img.src>` (broken cross-origin) | Uses canvas `drawImage` + `toDataURL` |
| 18 | No config.py — hardcoded values scattered | `app/core/config.py` with `pydantic-settings` |
| 19 | Missing `__init__.py` files | Added to all packages |
| 20 | No `.gitignore`, `Dockerfile`, `.env.example` | Added all three |
| 21 | CSS: 23 flagged duplicates (investigated) | All valid: compound/state selectors + @media overrides |
| 22 | `hmac.new()` signature check | Verified correct — uses `hmac.new(key, data, hash_fn)` |
| 23 | No `pydantic-settings` dependency | Added to `requirements.txt` |
| 24 | Toast could stack infinitely | Queue-based with `MAX=4` cap |
| 25 | Copy button: no visual feedback | Added `btn-copied` class with checkmark + timeout |
| 26 | `encApiBanner` always hidden | Now correctly reflects real-time API status |
| 27 | Compression page: no API requirement communicated | Offline banner shown when API unavailable |
| 28 | Missing `aria-label` on many controls | 85 `aria-label` attributes added |
| 29 | JWT parts collapsed to 1 col on mobile | Added responsive CSS for `.jwt-parts` |
| 30 | No page-level `aria-live` for dynamic content | 27 `aria-live` regions added |

---

## Features

### Encoding — 24 Algorithms (all roundtrip-verified)

| Group | Algorithms |
|-------|-----------|
| Base  | Base64, Base32, Base16, Base58, Base62, Base85 |
| Numeric | Hexadecimal, Binary, Octal, Decimal |
| Web | URL, HTML Entities, Unicode Escape, ASCII, Punycode |
| Ciphers | ROT13, Caesar, Vigenère, Atbash, Morse, Bacon, Rail Fence, Affine, Polybius |

### Hashing — 13 Algorithms
MD5 · SHA1 · SHA224 · SHA256 · SHA384 · SHA512 · SHA3-256 · SHA3-512 · BLAKE2b · BLAKE2s · RIPEMD160 · CRC32 · Adler32

### JWT — HS256 / HS384 / HS512
Decode (visual breakdown) · Generate (custom claims) · Verify (API + client-side HMAC)

### Compression
GZIP · ZLIB · LZMA · Brotli — with optional Base64 transport encoding

### Developer Tools
UUID v1/v4/v7 · NanoID · Password Generator (entropy) · Timestamp Converter · Color Converter (HEX/RGB/HSL) · Random String · Slug & Case Converter

### Data Formatters (client-side)
JSON format/minify/validate · YAML ↔ JSON · XML format/minify · SQL format/minify

---

## API Reference

### Base URL
```
http://localhost:8000
```

### Rate Limit
200 requests / 60 seconds per IP. Headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

### Routes

```
POST /api/encode              Encode text (24 algorithms)
POST /api/decode              Decode text
POST /api/detect              Auto-detect encoding format
POST /api/batch               Chain multiple operations

POST /api/hash                Generate hash (13 algorithms)
POST /api/hash/all            All hashes simultaneously
POST /api/hash/verify         Constant-time hash verification

POST /api/jwt/decode          Decode JWT (no sig check)
POST /api/jwt/generate        Generate signed JWT
POST /api/jwt/verify          Verify HMAC signature

POST /api/compress            Compress (GZIP/ZLIB/LZMA/Brotli)
POST /api/decompress          Decompress

POST /api/uuid                UUID v1/v4/v7 or NanoID
POST /api/password            Secure passwords + entropy
POST /api/random-string       Random strings (6 types)
POST /api/timestamp           Unix ↔ ISO/UTC conversion
POST /api/color               HEX/RGB/HSL conversion
POST /api/slug                Slug + case variants

GET  /health                  Health check
GET  /api/tools               List all algorithms
GET  /docs                    Swagger UI
GET  /redoc                   ReDoc
```

### Example

```bash
# SHA-256 hash
curl -X POST http://localhost:8000/api/hash \
  -H "Content-Type: application/json" \
  -d '{"text":"Hello","algorithm":"sha256"}'

# Base64 → Hex batch chain
curl -X POST http://localhost:8000/api/batch \
  -H "Content-Type: application/json" \
  -d '{"text":"Hello","steps":[{"algorithm":"base64","mode":"encode"},{"algorithm":"hex","mode":"encode"}]}'

# Generate JWT
curl -X POST http://localhost:8000/api/jwt/generate \
  -H "Content-Type: application/json" \
  -d '{"payload":{"role":"admin"},"secret":"secret","algorithm":"HS256","expires_in":3600}'
```

---

## Security Controls

| Control | Implementation |
|---------|----------------|
| Input validation | Pydantic v2 with size limits |
| Request size | 20 MB hard cap in middleware |
| Rate limiting | `asyncio.Lock`-protected sliding window, 200/60s |
| CORS | Explicit origin allowlist |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Hash verification | `hmac.compare_digest()` — constant-time |
| No content logging | User data never written to logs |
| Stateless | Zero persistence, no sessions |
| XSS protection | All frontend output uses `esc()` or `textContent` |

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `⌘ K` | Open search |
| `⌘ ⇧ C` | Copy current output |
| `⌘ .` | Go home |
| `Esc` | Close modal/drawer |

---

## Tech Stack

**Backend:** Python 3.12 · FastAPI 0.115 · Pydantic v2 + pydantic-settings · Uvicorn

**Frontend:** Vanilla HTML5/CSS3/ES2022 · Lucide Icons · CryptoJS · Motion (Framer Motion for web) · Web Crypto API · CompressionStream API

**No build step** — open `index.html` directly.
