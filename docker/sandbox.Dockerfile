# JEV Sentinel sandbox image — validators run here, never on the host.
# Tools are installed at build time (network is disabled at runtime).
#
# Build:  docker build -f docker/sandbox.Dockerfile -t jev-sentinel-sandbox:latest .
FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Core validation toolchain
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    ruff \
    mypy

# Common libraries so Python projects (incl. Sentinel itself) can run their tests offline
RUN pip install --no-cache-dir \
    "pydantic>=2.7.0" \
    "pydantic-settings>=2.3.0" \
    "fastapi>=0.110.0" \
    "httpx>=0.27.0" \
    "pyyaml>=6.0.1" \
    "sqlalchemy>=2.0.30" \
    "structlog>=24.1.0" \
    "typer>=0.12.0" \
    "rich>=13.7.0" \
    "gitpython>=3.1.43" \
    "python-multipart>=0.0.9" \
    "faker>=25.0.0" \
    "anyio>=4.0.0"

# Unprivileged user matching the executor's uid 1000:1000
RUN useradd -m -u 1000 sandbox && mkdir -p /workspace && chown sandbox:sandbox /workspace

USER sandbox
WORKDIR /workspace
