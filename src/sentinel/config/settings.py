"""Application settings — 12-factor, cloud-ready."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore", populate_by_name=True)

    # Environment
    sentinel_env: Literal["development", "production", "testing"] = Field(default="development", alias="SENTINEL_ENV")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")

    # Database
    database_url: str = Field(default="sqlite:///./sentinel.db", alias="DATABASE_URL")

    # Sentinel core
    sentinel_mode: Literal["gated", "advisory", "strict"] = Field(default="gated", alias="SENTINEL_MODE")
    max_retries: int = Field(default=3, alias="SENTINEL_MAX_RETRIES")
    max_diff_size: int = Field(default=5 * 1024 * 1024, alias="SENTINEL_MAX_DIFF_SIZE")
    max_file_size: int = Field(default=1 * 1024 * 1024, alias="SENTINEL_MAX_FILE_SIZE")
    max_output_size: int = Field(default=1 * 1024 * 1024, alias="SENTINEL_MAX_OUTPUT_SIZE")

    # Validation
    validation_timeout: int = Field(default=120, alias="VALIDATION_TIMEOUT")

    # Sandbox / Docker
    docker_enabled: bool = Field(default=True, alias="DOCKER_ENABLED")
    sandbox_image: str = Field(default="python:3.12-slim", alias="SANDBOX_IMAGE")
    sandbox_fallback_enabled: bool = Field(default=False, alias="SANDBOX_FALLBACK_ENABLED")

    # JEV
    jev_api_key: str | None = Field(default=None, alias="JEV_API_KEY")
    jev_api_url: str | None = Field(default=None, alias="JEV_API_URL")
    jev_enabled: bool = Field(default=False, alias="JEV_ENABLED")
    jev_timeout: int = Field(default=30, alias="JEV_TIMEOUT")

    # API
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    secret_key: str = Field(default="change-me", alias="SECRET_KEY")

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
                    data = yaml.safe_load(f) or {}
                    return data.get("sentinel", data)
        return {}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


def get_database_url() -> str:
    return get_settings().database_url
