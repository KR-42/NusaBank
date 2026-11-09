# NusaBank Lab — Dockerfile
#
# This image is for LOCAL PENETRATION-TESTING ONLY.
# It is intentionally vulnerable. DO NOT EXPOSE TO THE INTERNET.
#
# Build:   docker build -t nusabank .
# Run:     docker compose up --build
# Access:  http://127.0.0.1:8080

FROM python:3.11-slim-bookworm

# Install curl for the healthcheck; iputils-ping backs the admin diagnostics page
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create an unprivileged user
RUN groupadd --system --gid 1000 nusabank \
    && useradd --system --uid 1000 --gid nusabank --create-home --shell /usr/sbin/nologin nusabank

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY templates/ ./templates/
COPY static/ ./static/
COPY db/ ./db/
COPY docs/ ./docs/
COPY uploads/ ./uploads/
COPY entrypoint.sh /entrypoint.sh

# Create writable data directories owned by the unprivileged user
RUN mkdir -p /app/db /app/uploads /app/data \
    && chmod +x /entrypoint.sh \
    && chown -R nusabank:nusabank /app /entrypoint.sh

USER nusabank:nusabank

# Expose port (only published to 127.0.0.1 by docker-compose)
EXPOSE 8080

# Default environment
ENV LAB_LEVEL=medium \
    NUSABANK_DB=/app/db/nusabank.db \
    NUSABANK_UPLOADS=/app/uploads \
    NUSABANK_SECRET=nusabank-dev-secret-change-me \
    PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8080/health || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "app", "--host=0.0.0.0:8080"]