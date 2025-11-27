# Cerberus SAST - Production Dockerfile
# Multi-stage build for minimal image size

# Stage 1: Build stage
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

# Stage 2: Runtime stage
FROM python:3.12-slim as runtime

# Security: Run as non-root user
RUN groupadd -r cerberus && useradd -r -g cerberus cerberus

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY cerberus/ ./cerberus/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CERBERUS_HOME=/app

# Create directories for scans
RUN mkdir -p /scans /reports && \
    chown -R cerberus:cerberus /scans /reports /app

# Switch to non-root user
USER cerberus

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import cerberus; print('healthy')" || exit 1

# Default command - run as CLI
ENTRYPOINT ["python", "-m", "cerberus"]
CMD ["--help"]

# Expose API port (when running in server mode)
EXPOSE 8000
