FROM python:3.12-slim

WORKDIR /app

# System deps for git and build
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e .

# Copy rest of app
COPY sentinel.yaml ./
COPY alembic.ini ./
COPY alembic ./alembic

EXPOSE 8000

ENV SENTINEL_ENV=production
ENV PYTHONPATH=/app/src

# Apply migrations before serving; exit if they fail (no silent schema drift)
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn sentinel.api.main:app --host 0.0.0.0 --port 8000"]
