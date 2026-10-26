#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
case "$(uname -s)" in
    Darwin) pool=${CELERY_POOL:-solo}; concurrency=${CELERY_CONCURRENCY:-1} ;;
    *) pool=${CELERY_POOL:-prefork}; concurrency=${CELERY_CONCURRENCY:-2} ;;
esac
exec .venv/bin/celery -A app.celeryapp:celery worker --pool="$pool" --loglevel="${LOG_LEVEL:-info}" --concurrency="$concurrency"
