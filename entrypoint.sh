#!/bin/sh
# NusaBank lab entrypoint.
# Runs as an unprivileged user; only bind-mounted paths are writable.

set -e

mkdir -p "$(dirname "${NUSABANK_DB:-/app/db/nusabank.db}")" \
         "${NUSABANK_UPLOADS:-/app/uploads}" \
         /app/data

# Seed is idempotent: it exits immediately when users already exist.
if [ "${LAB_SEED:-1}" = "1" ] && [ -f /app/db/seed.py ]; then
  echo "[nusabank] ensuring lab database is seeded..."
  python /app/db/seed.py || echo "[nusabank] seed failed; continuing"
fi

exec "$@"