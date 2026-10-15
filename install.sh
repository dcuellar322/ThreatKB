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
    uv pip install --python .venv/bin/python --only-binary=:all: -r requirements-build.txt
    uv pip sync --python .venv/bin/python --no-build-isolation requirements-build.txt requirements-dev.txt
    uv pip check --python .venv/bin/python
else
    python3.14 -m venv .venv
    .venv/bin/python -m pip install --only-binary=:all: -r requirements-build.txt
    .venv/bin/python -m pip install --no-build-isolation -r requirements-dev.txt
    .venv/bin/python -m pip check
fi
if [ "${SKIP_FRONTEND_BUILD:-0}" != "1" ]; then
    if ! command -v npm >/dev/null 2>&1; then
        echo "Node.js/npm is required to build the workbench (or set SKIP_FRONTEND_BUILD=1 for CLI-only use)." >&2
        exit 1
    fi
    npm --prefix frontend ci --ignore-scripts --no-audit --no-fund
    npm run build
fi
.venv/bin/flask --app app db upgrade
