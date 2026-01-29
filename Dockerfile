# Stage 1: Build Svelte frontend
FROM node:20-alpine AS frontend

WORKDIR /web
COPY web/package*.json ./
RUN npm ci

COPY web/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.11-slim AS runtime

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install --no-cache-dir poetry==1.7.1

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install Python dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Copy application code
COPY filterdns/ ./filterdns/
COPY alembic/ ./alembic/
COPY alembic.ini ./
COPY blocklists.yaml ./

# Copy built frontend
COPY --from=frontend /web/build ./filterdns/static/

# Create data directory and set environment
RUN mkdir -p /app/data/blocklists
ENV FILTERDNS_BLOCKLIST_CACHE_DIR=/app/data/blocklists

# Create non-root user
RUN useradd -r -s /bin/false filterdns \
    && chown -R filterdns:filterdns /app

USER filterdns

# Expose ports
EXPOSE 53/udp 53/tcp 443 853 8080

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1

# Run the application
ENTRYPOINT ["python", "-m", "filterdns"]
