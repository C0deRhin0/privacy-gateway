from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(slots=True)
class Settings:
    upstream_base_url: str = os.getenv("PRIVACY_GATEWAY_UPSTREAM_BASE_URL", "http://127.0.0.1:18787/v1")
    host: str = os.getenv("PRIVACY_GATEWAY_HOST", "127.0.0.1")
    port: int = int(os.getenv("PRIVACY_GATEWAY_PORT", "14000"))
    strict_mode: bool = os.getenv("PRIVACY_GATEWAY_STRICT", "true").lower() in {"1", "true", "yes", "on"}


def get_settings() -> Settings:
    return Settings()
