#!/bin/sh
set -eu
if [ "${RUN_AGENT:-0}" = "1" ]; then
    exec celery -A app.celery worker --loglevel=info
fi
flask --app app db upgrade
if [ -n "${THREATKB_ADMIN_EMAIL:-}" ] && [ -n "${THREATKB_ADMIN_PASSWORD:-}" ]; then
    flask --app app admin-user --email "$THREATKB_ADMIN_EMAIL"
fi
exec waitress-serve --host="${LISTEN_ON:-0.0.0.0}" --port="${LISTEN_PORT:-5000}" app:app
