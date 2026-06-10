# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential \
      curl \
      git \
      nmap \
      hydra \
      sqlmap \
      nikto \
      gobuster \
      netcat-openbsd \
      ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Autoscan/requirements.txt /tmp/requirements.txt

RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt && \
    playwright install --with-deps chromium

COPY ./Autoscan /app/Autoscan
COPY ./llm /app/llm
COPY ./data /app/data

RUN mkdir -p /app/artifacts /app/logs

ENV PYTHONPATH=/app:/app/Autoscan \
    DATABASE_URL=postgresql+asyncpg://postgres:postgres@db:5432/intelligence_db

EXPOSE 8000

CMD ["uvicorn", "src.api.backend_main:app", "--host", "0.0.0.0", "--port", "8000"]

