# Local development

Use Python 3.14 and the locked dependencies:

```sh
uv venv --python 3.14
uv pip sync --python .venv/bin/python requirements.txt
export THREATKB_DATABASE_URL='mysql+pymysql://USER:PASSWORD@127.0.0.1:3307/threatkb?charset=utf8mb4'
.venv/bin/flask --app app db upgrade
.venv/bin/flask --app app admin-user --email you@example.com
.venv/bin/waitress-serve --listen=127.0.0.1:5000 app:app
```

The admin command prompts for a password; `THREATKB_ADMIN_PASSWORD` is also
supported for unattended local bootstrap. Credentials belong in local environment
variables, never tracked files. A generated session signing key is kept in ignored
`instance/secret-key`; set `THREATKB_SECRET_KEY` for shared deployments.

Run `./.venv/bin/python -m pytest`. Tests use an isolated in-memory database and
never drop local MySQL tables.

## Database migration and rollback

The original MySQL 5.7 server remains at port 3306. A logical snapshot was restored
to the dedicated `threatkb-mysql-2026` container at port 3307, running MySQL 26.7.0.
The backup is `/private/tmp/threatkb-before-modernization.sql`; preserve a copy in
your normal backup system. No original data directory is reused for a major upgrade.
Switch `THREATKB_DATABASE_URL` back to the original server to inspect the original
snapshot; changes made after cutover require explicit reconciliation before rollback.

For a new Docker installation, set `MYSQL_ROOT_PASSWORD`, `SQL_PASSWORD`, and
`THREATKB_SECRET_KEY`, optionally bootstrap admin variables, then run
`docker compose up --build`. Percent-encode reserved URL characters in SQL_PASSWORD.
The entrypoint exits on migration errors instead of starting a broken web server.

## Dependency refresh

```sh
uv pip compile requirements.in --python-version 3.14 --exclude-newer 2026-10-05T00:00:00Z --upgrade -o requirements.txt
```

`docs/python-dependency-audit.json` records the registry release date of every pin.

## Synthetic development data

Run `.venv/bin/flask --app app seed-dev --email you@example.com`. By default this
adds 2,500 signatures, 10,000 benchmark-network IPs, 5,000 `.example.test` domains,
and 400 tasks. It is repeatable: matching synthetic records are not duplicated and
existing records are not removed. Every synthetic signature has a benign sample
in `instance/dev-corpus`, with a SHA-256 reference in its YAML representation.
`instance/dev-content` is a separate local Git repository containing the generated
YAML signatures. Its first seed is committed automatically. Counts are configurable
with `--rules`, `--ips`, `--domains`, and `--tasks`. These are synthetic fixtures,
not intelligence or production-quality detections.

## DFI and sample preprocessing

Existing POSTPROCESSOR command settings remain supported, with `{FILENAME}` and
`{WORKDIR}` argument placeholders and a bounded POSTPROCESSOR_TIMEOUT (seconds).
DFI is optional and disabled by default, as authorized by the user. Uploads report
`postprocessing_skipped` when a configured DFI step is disabled; other processors
continue to run. To opt in later, set `POSTPROCESSOR_DFI_ENABLED=true` in the
environment or workspace settings. For DFI entries, set POSTPROCESSOR_DFI_IMAGE
to an explicit image tag or digest to
use a container adapter instead of a machine-specific pp-dev wrapper. It runs with
network disabled, receives the sample path under `/work`, and writes extracted
files into the mounted work directory. The external image must support that
entrypoint contract. No DFI image was available in this local installation, so
the vendor-specific integration is intentionally skipped. Explicitly enabling it
retains failure reporting; missing/broken tooling is never reported as a successful
DFI analysis. Command adapters and skip/error behavior are verified locally.

## Workbench, worker and scheduler

```sh
npm --prefix frontend ci --ignore-scripts
npm run build
LISTEN_PORT=5080 sh run_web.sh
# Separate terminals:
sh run_agent.sh
sh run_scheduler.sh
```

Open http://127.0.0.1:5080. For frontend development, `npm run dev` proxies API
requests to port 5080. The local restored workspace uses Redis at port 6380; the
Compose deployment uses its private `redis:6379` service. Configure
`REDIS_BROKER_URL` in your ignored environment or config file. Workers and beat
share the same database, instance paths and signing key as the web process.

Three preexisting invalid draft signatures in the restored copy (IDs 8–10) were
disabled, preserving their source and adding audit comments, so active compilation
can succeed. Repair them before restoring them. This affects only the new local
MySQL copy. The original database and its backup retain their original contents.

The development seed also provides 25 harmless goodware files under
`instance/dev-goodware`. Production validation needs a representative private
corpus; these fixtures prove mechanics and regression behavior only.

For the content schema, independent builders, review/promotion commands, consumer
contracts and rollback procedure, see [detection-as-code.md](detection-as-code.md).
