"""
ShadowCrypt++ — Application Configuration
All settings in one place, driven by environment variables.
"""

from __future__ import annotations

from functools import lru_cache
from typing import FrozenSet, List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────────
    app_name:    str = "ShadowCrypt++ API"
    app_version: str = "2.0.0"
    debug:       bool = False

    # ── Server ───────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000

    # ── Security ─────────────────────────────────────────────
    api_keys: List[str] = Field(default_factory=list, description="Comma-separated valid API keys")
    cors_origins: List[str] = Field(
        default_factory=lambda: [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "https://shadowcrypt.app",
        ]
    )

    # ── Rate limiting ─────────────────────────────────────────
    rate_limit_requests: int = 200
    rate_limit_window:   int = 60   # seconds

    # ── Request limits ────────────────────────────────────────
    max_body_bytes:  int = 20 * 1024 * 1024   # 20 MB
    max_text_bytes:  int = 10 * 1024 * 1024   # 10 MB

    @property
    def api_key_set(self) -> FrozenSet[str]:
        return frozenset(k.strip() for k in self.api_keys if k.strip())


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
