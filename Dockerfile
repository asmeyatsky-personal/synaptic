FROM python:3.12-slim

LABEL maintainer="SynapticBridge Team"
LABEL description="SynapticBridge MCP Orchestration Platform with Correction Learning Engine"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir .

COPY . .

RUN useradd -m -u 1000 synaptic && \
    chown -R synaptic:synaptic /app && \
    mkdir -p /var/lib/synaptic-bridge/audit && \
    chown synaptic:synaptic /var/lib/synaptic-bridge/audit

USER synaptic

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

STOPSIGNAL SIGTERM

CMD ["python", "-m", "uvicorn", "synaptic_bridge.presentation.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
