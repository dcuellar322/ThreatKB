#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.14 --allow-existing .venv
    uv pip sync --python .venv/bin/python requirements.txt
else
    python3.14 -m venv .venv
    .venv/bin/python -m pip install -r requirements.txt
fi
.venv/bin/flask --app app db upgrade
