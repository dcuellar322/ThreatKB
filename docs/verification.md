# Modernization verification — 2026-10-15

## Local evidence

- Personal fork master fast-forwarded 113 commits; rc synchronized; both divergent
  histories merged into `codex/2026-modernization` without force pushes.
- Python 3.14.7, Flask 3.1.3, SQLAlchemy 2.1.3, YARA 4.5.4 and React 19.3.0.
  Every one of 70 Python and 70 npm locked releases predates 2026-10-05 UTC.
- Full application image built successfully. Its isolated regression suite passed
  48 tests at the container checkpoint; subsequent changes add export coverage.
- Container boot against empty `threatkb_fresh_2026` applied the complete historical
  migration chain, created an administrator, and returned HTTP 200 for health,
  the React entrypoint, login and the authenticated empty dashboard.
- Restored local MySQL migrated to 26.7.0 on port 3307. Original 5.7 data on port
  3306 and its logical backup were retained.
- Seed: 2,500 synthetic signatures, 10,000 benchmark IPs, 5,000 test domains,
  400 tasks, SHA-256 sample corpus, YAML Git repository and 25 goodware fixtures.
- Real Redis/Celery validation job `300a72db-c343-4ce6-9188-d586c9b69eae`
  passed 1,250 eligible signatures, 1,250 positive samples and 25 goodware files.
  Separate Sigpack, Feedpack and Codepack jobs all completed successfully.
- Native YARA compilation of the restored active rules succeeded after preserving
  and disabling three preexisting invalid drafts in the development copy.
- Browser checks covered login, signature creation/search, transactional draft
  comment save, two independent uploads, selection/deletion of one attachment,
  sample-test queueing and full-text expansion. Responsive and Git editor checks
  are recorded in the final pass below.

## Operational footprint

The web workbench manages legacy signatures, IP/domain indicators, tasks, owners,
metadata, workflow states, macros, comments, revisions, bookmarks and releases.
The optional YAML editor commits into a separate content Git repository. The CLI
can validate and build content independently of Flask and the database.

MySQL persists operational records and job outcomes. Redis carries Celery work;
the worker performs validation/scans/builds and beat applies confidence schedules
and promotion checks. Sample storage and content/build/channel files live under
the ignored instance directory. Optional GeoLite databases enrich IPs. Analyst
scripts and explicitly configured postprocessors run locally with timeouts.
No email/Slack messages were sent during verification.

The original usability and runtime failures are mapped individually to their
fixes and evidence in `issue-resolution.md`. Installation/rollback and process
commands are in `local-development.md`; content workflow and consumer contracts
are in `detection-as-code.md`.

## External acceptance

The DFI container image/registry was not supplied and the old pp-dev wrapper is
absent. The user authorized skipping DFI on 2026-10-15. It is disabled by default
and uploads report configured DFI steps as skipped. Command adapters and explicit
enable/failure behavior are tested; vendor image compatibility is outside the
accepted local scope (#470). No unavailable production TAC/customer endpoint, collection
checkout or private corpus is treated as tested. Receiving-system UUID support,
channel polling, telemetry reporting and alert delivery require integration there.
Production promotion blocks without independent review and complete elapsed
telemetry; development does not manufacture those signals. Actual release-frequency
improvement requires real usage and is measured rather than asserted.

## Final local pass

The final container suite passed all 50 tests without warnings, including Git
authoring, immutable UUIDs, review gates and legacy-to-Feedpack selection/export.
`uv pip check` reports all 70 installed packages compatible. TypeScript checking and
production bundling pass. Desktop (1440 px) and mobile (390 px) screenshots were
inspected; the final visual pass corrected a collapsed mobile heading, enlarged
touch/input controls and removed hidden navigation from keyboard focus. Generated
screenshots remain in ignored `output/playwright`.

GitHub push and PR workflows both passed at commit `5700089`, including the full
image build, regressions and all three independent pack pipelines. Browser Git
authoring created and updated a draft as separate commits in the development
content repository.

Final follow-ups preserve EventID/UUID during bulk category changes and separate
positive/negative histories. Real queued tests of the browser-created signature
matched its attached positive sample and passed all 25 goodware files. The mobile
pass also verified Escape closes navigation, hidden navigation is inert, and the
390 px page has no horizontal overflow. Failed-login feedback and return to the
requested Tasks route were exercised in the browser.

Fork master now requires the `verify` status check, an independent PR approval
(including approval after the last push), resolved review conversations and stale
approval dismissal. These rules apply to administrators; force pushes and branch
deletion are disabled. The modernization PR remains a draft for independent review.

## Performance and UI review follow-up

The October 2026 follow-up passes **70 tests locally and in the production Docker image**. All independent Sigpack, Feedpack and Codepack pipelines pass in that image. MySQL migrations were applied to the main development database and a separate browser-QA database. The frontend production build and unused-declaration checks pass. Real-browser workflows and before/after query measurements are recorded in [2026-review.md](2026-review.md); screenshots remain local under `output/playwright/`.
