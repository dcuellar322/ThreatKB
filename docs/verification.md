# Modernization verification — 2026-10-15

## Current repository evidence

- **111 backend/content tests pass locally**, including dependency-age policy,
  staged-index preservation, IOC assessment, reviewed publication, frozen promotion
  policy, alarm visibility and the prior application/query/permission regressions.
- Frontend type checking/build and Prettier checks pass. Python correctness lint,
  formatting and shell syntax checks pass. Thirty-two legacy invalid string escapes
  were corrected with parsed-AST equivalence verified; regex values are unchanged.
- Live registry audits cover **72 Python distributions and 87 npm distributions**.
  Container/action/Rust evidence covers seven infrastructure records. Every selected
  input predates the conservative 2026-10-05 UTC cutoff. See
  [dependency-policy.md](dependency-policy.md).
- The rebuilt production stack boots from empty, separate MySQL/Redis/workspace
  volumes on ports 15080/13307/16380. Authenticated TCP readiness avoids the MySQL
  initialization race. Migrations, admin bootstrap, health, frontend and login pass.
  Database fields preserve reserved password characters; Redis has a persistent
  data volume alongside MySQL and the application workspace.
- A real Celery validation job on that isolated stack completes successfully against
  generated samples and 25 goodware fixtures. Scheduler state is on the persistent
  workspace volume. Runtime UID is 1000; pytest, Ruff and GCC are absent from the
  production image.
- A separate native checkout/venv installs from the locks, builds cryptography/YARA,
  compiles the frontend, checks dependency compatibility and applies migrations.
  It uses the isolated MySQL database, not the main development database.
- CI now separates quality, application and per-pack jobs with retained artifacts
  and an always-run `verify` aggregate. Reviewed testing publication is implemented,
  tested at a mocked GitHub boundary, and remains opt-in; no release was published.

The maintenance browser check also verifies creating a task through the fresh
native installation, reopening its permalink, persistent release alarms at desktop
and 390px widths, notification clearing without clearing the channel alarm, and
the preserved main-app login/content page after the image replacement. It found
and fixed a shared mobile rule hiding the alarm badge. No page errors or horizontal
page overflow were observed. Four screenshots and a gallery are available locally
under `output/playwright/maintenance-2026-10-15/`; generated browser evidence is
intentionally excluded from Git.

## Content-page performance follow-up

The [content execution/performance report](content-performance.md) records the
current worker/Git boundaries and a measured warm API median reduction from
276 ms to 68 ms on 2,502 YAML signatures. It includes external-edit invalidation
regressions, browser search/pagination/history checks and a successful real queued
validation of 1,250 selected rules, their positive samples, and 25 goodware samples.
The verification workflow runs the current suite in its Python 3.14 container.

## Existing application and browser evidence

The preceding [end-to-end audit](browser-e2e-2026-10-15.md) records table filters,
sorting/pagination, artifact CRUD/merge/revisions, metadata, files, imports, account
credentials/keys, roles, content builds/review and releases. It includes desktop and
mobile navigation across all 18 pages, rapid permalink reopening, failure recovery,
and 46 selected screenshots. The earlier [UI audit](ui-audit-2026-10-15.md) covers
all page and dialog families. Browser mutations use separate databases/instance
paths/queues. Chromium is the verified browser; Safari/Firefox are not claimed.

The prior work also verified a fresh complete migration chain, legacy export,
immutable UUIDs, all three content builders and hundreds of synthetic content/sample
checks. [2026-review.md](2026-review.md) records query measurements and limitations:
seeded signature listing falls from 203 SQL calls / 915 ms to 9 calls / 37 ms; IP
listing falls from 128 calls / 444 ms to 8 calls / 40 ms. Macro expansion reuses one
batched query instead of 101 calls for fifty rules. Those measurements describe
that fixture/run, not a production latency guarantee.

## Preserved local runtime and rollback

Upstream master `83fde23` and rc `d57fa30` are both included in the draft
modernization PR. All 40 open upstream issues have recorded resolutions, with the
explicit DFI exception; upstream issue state was not changed. The fork's protected
master requires `verify`, independent approval after the last push, resolved
conversations and stale approval dismissal, including for administrators.

The main development web/worker/scheduler use preserved MySQL 26.7 data on port
3307 and Redis 8.10.2 on port 6380. Container image replacement retained the same
software versions, backed up the databases/Redis, retained stopped rollback
containers, and added a persistent Redis volume. Original MySQL 5.7 and the
pre-modernization logical snapshot remain available. See the
[local guide](local-development.md) for exact backup/rollback details.

## External acceptance remains explicit

The vendor DFI integration is skipped under the user's authorization; default
uploads report that skip and explicitly enabled adapter failures remain errors.
No vendor image compatibility, private corpus coverage, customer/TAC deployment,
collection-update operation or external enrichment accuracy is claimed.

The generic pack builders, IOC assessment and local channel engine are implemented.
GitHub testing publication requires explicit activation and a real independently
approved merge in the intended content repository. Receiving systems still need
UUID/pack compatibility, frequent polling, telemetry delivery and external alarm
routing. Production promotion blocks without real elapsed telemetry; no operational
signals or release-frequency improvement are fabricated. Authoritative migration
away from legacy signature management and the target doubling of release frequency
require real team cutover and usage. [design-acceptance.md](design-acceptance.md)
records the implemented-versus-remaining matrix.
