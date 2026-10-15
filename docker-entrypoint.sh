#!/bin/sh
set -eu
if [ "$#" -gt 0 ]; then
    exec "$@"
fi
role=${THREATKB_ROLE:-web}
if [ "${RUN_AGENT:-0}" = "1" ]; then role=worker; fi
case "$role" in
    worker)
        exec celery -A app.celeryapp:celery worker --loglevel="${LOG_LEVEL:-info}" --concurrency="${CELERY_CONCURRENCY:-2}"
        ;;
    scheduler)
        instance=${THREATKB_INSTANCE_PATH:-/opt/threatkb/instance}
        mkdir -p "$instance"
        exec celery -A app.celeryapp:celery beat --schedule="$instance/celerybeat-schedule" --loglevel="${LOG_LEVEL:-info}"
        ;;
    web)
        flask --app app db upgrade
        if [ -n "${THREATKB_ADMIN_EMAIL:-}" ] && [ -n "${THREATKB_ADMIN_PASSWORD:-}" ]; then
            flask --app app admin-user --email "$THREATKB_ADMIN_EMAIL"
        fi
        exec waitress-serve --host="${LISTEN_ON:-0.0.0.0}" --port="${LISTEN_PORT:-5000}" app:app
        ;;
    *)
        echo "Unknown THREATKB_ROLE: $role (choose web, worker, or scheduler)" >&2
        exit 2
        ;;
esac
