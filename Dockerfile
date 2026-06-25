# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev libssl-dev curl && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "hatchling" && \
    pip install --no-cache-dir "asyncpg>=0.30.0" && \
    pip install --no-cache-dir .[full]

# ── Runtime stage ──────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NAVMAX_DATA_DIR=/data/navmax \
    NAVMAX_DB_URL=sqlite+aiosqlite:///data/navmax/navmax.db

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates nmap && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY . .

RUN mkdir -p /data/navmax /data/nuclei

# Sécurité : utilisateur non-root
RUN groupadd -r navmax --gid=1001 && \
    useradd -r -g navmax --uid=1001 --home-dir=/app --no-create-home navmax && \
    chown -R navmax:navmax /app /data/navmax /data/nuclei

USER navmax

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/api/v1/health || exit 1

CMD ["uvicorn", "navmax.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
