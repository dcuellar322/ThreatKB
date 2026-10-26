# ThreatKB

A detection engineering workbench for YARA signatures, IP/domain intelligence,
analyst reviews and versioned content releases. This fork runs Python 3.14.7,
Flask 3 and React, with MySQL 26.7 and Redis 8.10.2.

## Run with Docker

```sh
cp .env.example .env
# Replace the credential/signing-key placeholders in .env.
docker compose up -d --build --wait
docker compose exec web flask --app app admin-user --email you@example.com
```

Open http://127.0.0.1:5080. The admin command prompts for a password. Compose
starts the web app, worker and scheduler after authenticated database readiness;
its named volumes retain database data, files, Git content and scheduler state.
Native MySQL on port 3306 is not reused. Set `WEB_PORT`, `MYSQL_PORT` and
`REDIS_PORT` to run a separate stack without port conflicts.

## Run natively

Install uv, patched Node.js/npm (26.12.1 from `.node-version`, or 24.22.1+),
libmagic, OpenSSL, pkg-config and C build tools. Intel macOS
also needs Rust/rustup to compile the pinned cryptography release; the repository
pins the Rust toolchain. Configure native database/Redis URLs in `.env`, then:

```sh
sh install.sh
.venv/bin/flask --app app admin-user --email you@example.com
sh run_web.sh
# Separate terminals:
sh run_agent.sh
sh run_scheduler.sh
```

The installer selects Python 3.14.7, syncs pinned build/development dependencies,
builds the frontend and applies migrations. Web startup automatically prewarms the detection catalog in a separate process
without waiting for it to finish. The local worker uses the solo pool
on macOS and prefork on Linux. Native Windows uses WSL2; `install.bat` delegates
to WSL. See the [local guide](docs/local-development.md) for prerequisites,
CLI-only installation, configuration, synthetic data, backups and rollback.

## Detection and intelligence as code

The standalone `threatkb_content` package needs neither Flask services nor MySQL.
It validates Git-backed YAML signatures, assigns stable UUIDs, expands bounded
macros, verifies sample/goodware corpora and builds independent packs. Optional
IOC assessment normalizes observations, applies source trust/expiry/allowlist
policy, attaches local enrichment and exports independently reviewed indicators.

```sh
.venv/bin/python -m threatkb_content --root detections check --corpus detections/samples --goodware detections/goodware
.venv/bin/python -m threatkb_content --root detections build --kind feedpack
.venv/bin/python -m threatkb_content --root detections build --kind sigpack --corpus detections/samples --goodware detections/goodware
```

The public example and development seeds are harmless synthetic content. The web
editor remains optional. See [content authoring](docs/detection-as-code.md),
[IOC assessment](docs/intelligence-pipeline.md), and
[CI/testing publication](docs/content-delivery.md).

## Maintenance and verification

```sh
.venv/bin/python -m pytest -q
PATH="$PWD/.venv/bin:$PATH" sh scripts/check_backend.sh
npm run format:check --prefix frontend
npm run build
```

- [Ten-day dependency/build-input policy](docs/dependency-policy.md)
- [Design acceptance and remaining integration work](docs/design-acceptance.md)
- [Upstream issue resolutions](docs/issue-resolution.md)
- [Verification evidence](docs/verification.md)
- [Content-page execution and performance](docs/content-performance.md)
- [Browser workflow audit](docs/browser-e2e-2026-10-15.md)

CI has separate application, quality and per-pack jobs. A failing Sigpack job
cannot cancel Feedpack or Codepack; successful packs are retained as artifacts.
The protected branch's required `verify` check aggregates every job. Optional
GitHub testing publication requires approval of the final merged PR head and
validates source/pack checksums before any external write. Production promotion
still requires real elapsed telemetry; external product integration is not
claimed complete.

Original project: [InQuest/ThreatKB](https://github.com/InQuest/ThreatKB).
YARA parsing uses [Plyara](https://github.com/plyara/plyara).

## Brotli runtime security

CVE-2026-111497 requires patched Node 24.22.1+ or 26.12.1+. Frontend
installs enforce these floors. Docker pins Node 26.12.1 by immutable digest,
validates decoder behavior and built assets in CI, and copies only the workbench
assets into the Python application image. Rebuild existing images to apply the
update. See [the dependency policy](docs/dependency-policy.md) for the narrow
security exception to the usual release-age requirement.
