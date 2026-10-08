# ============================================
# CyberBank: Operation BlackVault
# Platform Dockerfile
# ============================================
# Multi-stage is overkill here — single stage with slim base
# ============================================

FROM python:3.12-slim

# Prevent Python from buffering stdout/stderr (important for Docker logs)
ENV PYTHONUNBUFFERED=1 \
 PYTHONDONTWRITEBYTECODE=1 \
 PIP_NO_CACHE_DIR=1

# Set working directory
WORKDIR /app

# Install system dependencies required by PyMySQL/cryptography
RUN apt-get update && \
 apt-get install -y --no-install-recommends \
 gcc \
 libffi-dev \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user for security
RUN adduser --disabled-password --gecos "" appuser && \
 chown -R appuser:appuser /app
USER appuser

# Expose Flask port
EXPOSE 5000

# Health check for the platform container
HEALTHCHECK --interval=15s --timeout=5s --retries=3 --start-period=10s \
 CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run with gunicorn in container
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 --timeout 120 'app:create_app()'"]
