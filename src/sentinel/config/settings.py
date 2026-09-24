"""Application settings — 12-factor, cloud-ready."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False)

    # Environment
    sentinel_env: Literal["development", "production", "testing"] = Field(default="development")
    log_level: str = Field(default="INFO")

    # Database
    database_url: str = Field(default="sqlite:///./sentinel.db")

    # Sentinel core
    sentinel_mode: Literal["gated", "advisory", "strict"] = Field(default="gated")
    max_retries: int = Field(default=3)
    max_diff_size: int = Field(default=5 * 1024 * 1024)
    max_file_size: int = Field(default=1 * 1024 * 1024)
    max_output_size: int = Field(default=1 * 1024 * 1024)

    # Validation
    validation_timeout: int = Field(default=120)

    # Sandbox / Docker
    docker_enabled: bool = Field(default=True)
    sandbox_image: str = Field(default="python:3.12-slim")
    sandbox_fallback_enabled: bool = Field(default=False)

    # JEV
    jev_api_key: str | None = Field(default=None)
    jev_api_url: str | None = Field(default=None)
    jev_enabled: bool = Field(default=False)
    jev_timeout: int = Field(default=30)
    jev_model: str = Field(default="typesafe/jev-1.13")

    # API
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    secret_key: str = Field(default="change-me")

    # Feature flags
    frontend_enabled: bool = Field(default=False)

    @property
    def is_production(self) -> bool:
        return self.sentinel_env == "production"

    @property
    def is_testing(self) -> bool:
        return self.sentinel_env == "testing"

    def load_yaml_overrides(self, path: Path | None = None) -> dict:
        """Load sentinel.yaml if present — for policy/config overrides."""
        candidates = [path] if path else [Path("sentinel.yaml"), Path("sentinel.yml"), Path("config/sentinel.yaml")]
        for p in candidates:
            if p and p.exists():
                with open(p, encoding="utf-8") as f:
                    data: dict = yaml.safe_load(f) or {}
                    overrides = data.get("sentinel", data)
                    return overrides if isinstance(overrides, dict) else {}
        return {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


def get_database_url() -> str:
    return get_settings().database_url
