#!/bin/sh
set -eu
python -m ruff check app threatkb_content scripts tests migrations setup.py
python -m ruff format --check app threatkb_content scripts tests migrations setup.py
python scripts/audit_dependencies.py --offline
for script in install.sh run_web.sh run_agent.sh run_scheduler.sh docker-entrypoint.sh .githooks/pre-commit; do
    sh -n "$script"
done
bash -n wait-for-it.sh
