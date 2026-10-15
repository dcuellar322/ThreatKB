#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
exec .venv/bin/waitress-serve --host="${LISTEN_ON:-127.0.0.1}" --port="${LISTEN_PORT:-5080}" app:app
