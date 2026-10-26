#!/bin/sh
set -eu
cd "$(dirname "$0")"
if [ -f .env ]; then
    set -a
    . ./.env
    set +a
fi
# rustup is commonly installed outside the shell PATH on Intel macOS.
if ! command -v cargo >/dev/null 2>&1 && [ -x "$HOME/.cargo/bin/cargo" ]; then
    PATH="$HOME/.cargo/bin:$PATH"
    export PATH
fi
CARGO_HOME=${CARGO_HOME:-$PWD/.build-tools/cargo}
CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$PWD/.build-tools/cargo-target}
export CARGO_HOME CARGO_TARGET_DIR
if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.14.7 --allow-existing .venv
    uv pip install --python .venv/bin/python --only-binary=:all: -r requirements-build.txt
    uv pip sync --python .venv/bin/python --no-build-isolation requirements-build.txt requirements-dev.txt
    uv pip check --python .venv/bin/python
else
    python3.14 -m venv .venv
    .venv/bin/python -c 'import sys; sys.exit(0 if sys.version_info[:3] == (3, 14, 7) else "Use Python 3.14.7, or install uv to select the pinned interpreter.")'
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
