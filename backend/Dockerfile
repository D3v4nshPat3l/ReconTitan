# ══════════════════════════════════════════════════
# ReconTitan — Production Dockerfile
# Multi-stage build: deps cached separately from code
# Same image used for both API server and Celery worker
# ══════════════════════════════════════════════════

# ── Stage 1: Build deps ──────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime ─────────────────────────────
FROM python:3.14-slim AS runtime

# Security: run as non-root
RUN groupadd --gid 10001 recontitan && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin recontitan

# System tools used by scan tasks
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        wget \
        git \
        nmap \
        whois \
        dnsutils \
        net-tools \
        iputils-ping \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /install /usr/local

WORKDIR /app

# Copy application code
COPY . .

# Frontend served from /frontend (mounted as volume in compose)
ENV FRONTEND_PATH=/frontend

# Own the workdir
RUN mkdir -p /tmp/recontitan && chown -R recontitan:recontitan /app /tmp/recontitan

USER recontitan

EXPOSE 8000

# Default CMD: production API server (no reload, no server header)
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--no-server-header", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "172.16.0.0/12"]
