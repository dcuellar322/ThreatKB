# Local development and containers

## Configuration and services

Copy `.env.example` to `.env` and replace its placeholders. All native launchers
source `.env`. `THREATKB_DATABASE_URL` is an SQLAlchemy URL; percent-encode reserved
characters in its password. `THREATKB_SECRET_KEY` is the shared signing key for
multi-process deployments. Without an override, native development creates an
ignored `instance/secret-key` with owner-only permissions. Use absolute paths for
`THREATKB_INSTANCE_PATH`, `CONTENT_REPOSITORY` and `CONTENT_CORPUS` overrides.

```sh
cp .env.example .env
# Edit credentials and the signing key before starting services.
docker compose up -d --build --wait
docker compose exec web flask --app app admin-user --email you@example.com
```

Default endpoints are web `127.0.0.1:5080`, MySQL `127.0.0.1:3307`, and Redis
`127.0.0.1:6380`. Container clients use internal `db:3306` and `redis:6379` addresses;
Compose supplies separate database host/user/password fields, overriding the native
URL from `.env` and preserving reserved characters in raw passwords. Override
`WEB_PORT`, `MYSQL_PORT` and `REDIS_PORT` for a separate stack and use a different
Compose project name to get separate volumes.

Exported shell variables take precedence over `.env` and Compose `--env-file`
values. Unset conflicting `SQL_PASSWORD`, port and bootstrap variables before
starting an isolated stack with a different environment file.

The database probe waits for authenticated TCP queries, avoiding MySQL's temporary
initialization socket. Web startup applies migrations and stops on failure.
Worker/scheduler wait for web health and use the same database and workspace.
Beat state is stored on the persistent workspace volume; Redis has its own data
volume. `THREATKB_ROLE` selects
web, worker or scheduler; legacy `RUN_AGENT=1` remains supported. A supplied Docker
command is executed directly for maintenance. Standalone image health checks
expect port 5000; the normal Compose deployment keeps that internal port.

Bootstrap can use `THREATKB_ADMIN_EMAIL` and `THREATKB_ADMIN_PASSWORD` for an
unattended fresh installation. Remove the bootstrap password after account creation
to avoid resetting it on subsequent starts. The interactive `admin-user` command
can create or recover a local administrator.

## Native installation

Use Python 3.14.7 (uv can provision it), Node.js/npm, C build tools, libmagic,
OpenSSL and pkg-config. Intel macOS must build cryptography from source and needs
Rust/rustup. `rust-toolchain.toml` selects the age-audited compiler; the installer
finds the standard `~/.cargo/bin` location when absent from PATH. Python build
backends are separately pinned. Cargo cache/build files default to ignored
`.build-tools/` instead of modifying the application's source. Native Windows is
not verified; `install.bat` uses WSL2, where Linux prerequisites apply.

Configure the local database/Redis URLs in `.env`, then:

```sh
sh install.sh
.venv/bin/flask --app app admin-user --email you@example.com
sh run_web.sh
# Separate terminals, using the same .env and instance paths:
sh run_agent.sh
sh run_scheduler.sh
```

Installation syncs production, development and build locks, checks compatibility,
builds the frontend, and applies migrations. `SKIP_FRONTEND_BUILD=1 sh install.sh`
provides CLI/backend-only installation. Worker defaults are solo/one process on
macOS and prefork/two processes on Linux; override `CELERY_POOL`,
`CELERY_CONCURRENCY` and `LOG_LEVEL` if appropriate.

Frontend development uses `npm run dev`; Vite proxies API requests to port 5080.
`THREATKB_BACKEND_URL` changes that target. `npm run build` from the repository root
builds the workbench into `app/static/workbench`; that generated directory is
ignored. Port 5080 is the native launcher's default; `LISTEN_PORT` and `LISTEN_ON`
can override it.

Waitress is the supported WSGI server in both launch paths. The obsolete
`uwsgi.yaml` was removed because it referenced the old virtual environment and
an uninstalled server; use `run_web.sh` or the Docker web role instead.

## Checks and image targets

```sh
.venv/bin/python -m pytest -q
PATH="$PWD/.venv/bin:$PATH" sh scripts/check_backend.sh
npm run format:check --prefix frontend
npm run build

docker build --target quality -t threatkb:quality .
docker build --target verification -t threatkb:verify .
docker run --rm --entrypoint python threatkb:verify -m pytest -q
docker build --target content -t threatkb:content .
```

The default/`production` image excludes development packages and compilers. The
`verification` target adds locked test/lint tools with writable temporary caches.
The `quality` target checks backend/frontend/configuration formatting, lint and
ages. The `content` target needs no frontend build or database/Redis services.
Containers run as a non-root user. When mounting a host artifact directory for CLI
builds, use `--user "$(id -u):$(id -g)"` so generated files have the host owner's IDs.

Tests use SQLite in memory and separate temporary instance directories. They do
not drop local MySQL tables or write into the development content/channel store.
See [dependency-policy.md](dependency-policy.md) for refresh/audit commands.

## Synthetic data and optional integrations

`.venv/bin/flask --app app seed-dev --email you@example.com` creates a repeatable
synthetic dataset: 2,500 signatures, 10,000 benchmark-network IPs, 5,000 test
domains, 400 tasks, per-rule hash-referenced samples and 25 goodware files. Counts
are configurable with `--rules`, `--ips`, `--domains`, `--tasks`. Its content Git
repository is `instance/dev-content`, with samples under `instance/dev-corpus`.
Existing records are retained. These fixtures prove behavior, not detection quality.

DFI remains disabled under the user's authorized exception. Existing POSTPROCESSOR
commands support `{FILENAME}`, `{WORKDIR}` and a bounded timeout. Disabled DFI steps
are explicitly reported skipped. To enable later, configure
`POSTPROCESSOR_DFI_ENABLED=true` and an actual `POSTPROCESSOR_DFI_IMAGE` tag/digest;
the adapter mounts `/work`, disables container networking and expects the agreed
vendor entrypoint contract. Enabled failures are reported, not treated as success.
Vendor compatibility is unverified.

For versioned content, IOC assessment and reviewed publication, see
[detection-as-code.md](detection-as-code.md),
[intelligence-pipeline.md](intelligence-pipeline.md), and
[content-delivery.md](content-delivery.md).

## Backups and rollback on this development machine

Original MySQL 5.7 remains on port 3306. The upgraded development database uses
MySQL 26.7 on port 3307 and its separate `threatkb_mysql_2026` volume. The original
logical snapshot is `/private/tmp/threatkb-before-modernization.sql`. Before the
2026-10-15 image pin replacement, all local databases were also backed up to
`/private/tmp/threatkb-before-image-pin-20261015.sql`, with Redis state in the
matching `.rdb` file. Copy backups into your normal backup system; `/private/tmp`
is not durable archival storage.

The age-pin replacement retained the same MySQL/Redis versions and MySQL volume;
stopped `*-before-age-pin` containers are rollback references. Stop replacement
containers before restoring an old container against the same data. Redis now has
a dedicated persistent `threatkb_redis_2026` volume. Do not use `docker compose down -v`
against development volumes as a reset shortcut. A different Compose project
and ports provide isolated fresh-install verification.

Switching to the original 5.7 snapshot does not reconcile later writes. Likewise,
Git revert creates a new content revision/build; it does not edit historical
manifests or bypass testing/promotion gates. Three invalid preexisting drafts
(IDs 8–10) were retained but deactivated in the upgraded copy; repair them before
reactivation.

## Automatic catalog prewarming

`run_web.sh` and the Docker web entrypoint automatically start a separate process
to prepare the catalog cache while the web server starts serving. No manual step,
Redis availability, or worker is required. The shared instance cache survives
web-process restarts; external edits invalidate affected entries. Startup failures
are logged and normal source loading remains available. The first-ever build
still parses source files, so an immediate catalog request can take the cold path
until the background work finishes.

Set `THREATKB_CATALOG_PREWARM=0` to disable automatic warming. Custom WSGI serving
should use `app.web:app`; Flask development serving can use
`.venv/bin/flask --app app.web run`. Migrations and administrative commands retain
`--app app` and do not launch warmers. The manual
`.venv/bin/flask --app app warm-content-catalog` command remains available for
diagnostics; it is no longer required for normal startup. The cache does not
replace worker validation or publication gates. See
[content-performance.md](content-performance.md).
