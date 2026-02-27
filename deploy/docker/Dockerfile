# OCI Observability Overview - Production Dockerfile
# Multi-stage build for optimized image
#
# Supports: Docker, OCI Container Instances, OKE
# All configuration via environment variables — no baked-in config files.

# Stage 1: Build stage
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Production stage
FROM python:3.11-slim AS production

# Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -d /home/appuser -m appuser

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY server/ ./server/
COPY web/ ./web/

# Set ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Environment variables — all configurable at runtime
ENV PATH=/home/appuser/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APP_PORT=9010 \
    APP_WORKERS=4 \
    ENVIRONMENT=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request; urllib.request.urlopen('http://localhost:'+os.environ.get('APP_PORT','9010')+'/health')"]

# Expose default port (override APP_PORT at runtime for different port)
EXPOSE 9010

# Use shell form for variable expansion
ENTRYPOINT ["sh", "-c", "exec uvicorn server.main:app --host 0.0.0.0 --port $APP_PORT --workers $APP_WORKERS"]
