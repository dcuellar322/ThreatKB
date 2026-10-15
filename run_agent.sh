#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
exec .venv/bin/celery -A app.celeryapp:celery worker --loglevel="${LOG_LEVEL:-info}" --concurrency="${CELERY_CONCURRENCY:-2}"
