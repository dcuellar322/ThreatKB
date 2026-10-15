# ThreatKB

A detection engineering workbench for YARA signatures, IP/domain intelligence,
analyst reviews and versioned content releases. This maintained fork replaces the
AngularJS/Bower frontend with React and runs on Python 3.14, Flask 3 and modern MySQL.

## Run locally

```sh
uv venv --python 3.14
uv pip sync --python .venv/bin/python requirements.txt
npm --prefix frontend ci --ignore-scripts
npm run build
export THREATKB_DATABASE_URL='mysql+pymysql://USER:PASSWORD@127.0.0.1:3307/threatkb?charset=utf8mb4'
export REDIS_BROKER_URL='redis://127.0.0.1:6380/0'
.venv/bin/flask --app app db upgrade
.venv/bin/flask --app app admin-user --email you@example.com
LISTEN_PORT=5080 sh run_web.sh
```

Open http://127.0.0.1:5080. Run `sh run_agent.sh` and `sh run_scheduler.sh` in
separate terminals for queued jobs, scheduled confidence changes and promotion
checks. The administrator command prompts for a password. For a fresh Docker
installation, configure the required environment variables described in the
[local guide](docs/local-development.md), then run `docker compose up --build`.

## Detection as code

The standalone `threatkb_content` package validates Git-backed YAML signatures,
assigns stable UUIDs, expands bounded Jinja macros, verifies sample/goodware corpora
and produces independent Sigpack, Feedpack and Codepack artifacts. Content review
and elapsed telemetry gates protect testing-to-production promotion. The web
editor is optional; the CLI needs neither MySQL nor the web application.

```sh
.venv/bin/python -m threatkb_content --root detections check --corpus detections/samples --goodware detections/goodware
.venv/bin/python -m threatkb_content --root detections build --kind sigpack --corpus detections/samples --goodware detections/goodware
```

See the [content workflow](docs/detection-as-code.md) for schemas, macros,
collections, reviewer policies, independent pack builds, channels and rollback.
The included example and development seeds contain harmless synthetic content.

## Maintenance and verification

- [Local services, migration, seed data and rollback](docs/local-development.md)
- [Modernization scope and upstream synchronization](docs/modernization.md)
- [Individual upstream issue resolutions](docs/issue-resolution.md)
- [Verification evidence and external integration limits](docs/verification.md)

Run `.venv/bin/python -m pytest -q` for isolated backend/content regressions and
`npm run build` for TypeScript and production frontend checks. Registry release
dates for every dependency pin are recorded under `docs/*dependency-audit.json`.
CI builds the full image and runs application and independent content checks.

Original project: [InQuest/ThreatKB](https://github.com/InQuest/ThreatKB).
YARA parsing uses [Plyara](https://github.com/plyara/plyara).
