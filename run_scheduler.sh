#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
instance=${THREATKB_INSTANCE_PATH:-instance}
mkdir -p "$instance"
exec .venv/bin/celery -A app.celeryapp:celery beat --schedule="$instance/celerybeat-schedule" --loglevel="${LOG_LEVEL:-info}"
