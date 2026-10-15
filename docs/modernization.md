# ThreatKB modernization

Started 2026-10-15. Dependency cutoff: 2026-10-05 (stable releases only).

## Delivery sequence

1. Restore Python 3.14 startup, modern dependency resolution, local database and login.
2. Address each open upstream issue independently, recording verification and commits.
3. Replace AngularJS/Bower with a maintained frontend and verify key workflows.
4. Complete Flask modernization, configuration, task integration and API checks.
5. Implement the Detection Signature Management Uplift plan in phases.
6. Complete responsive, accessible UI/UX review and end-to-end validation.

## Baseline

- Origin was InQuest/ThreatKB; the verified personal fork is dcuellar322/ThreatKB.
- Existing staged changes in search pagination and IP comment caching belong to the user.
- Local MySQL is 5.7.44; preserve its data before any server migration.
- Legacy services: Flask API, SQLAlchemy/MySQL, Celery/Redis, filesystem samples,
  GeoLite databases, optional Slack notifications and analyst-defined scripts.
- Existing UI: AngularJS, Bower and Grunt, with locally missing/unreliable assets.
- Upstream open issue inventory is preserved in `upstream-issues.json`.

## Uplift acceptance checklist

- [ ] Document footprint and migration/rollback procedures.
- [ ] Independent detection, intelligence and software content pipelines.
- [ ] Git-backed YAML signatures and import/export from the legacy store.
- [ ] Jinja macro lists, filters and bounded expansion with compilation checks.
- [ ] Category-derived names, rich metadata tags and separate workflow state.
- [ ] UUID identifiers stable across renames; UUID-based heater/cooler pairings.
- [ ] Sample-hash references, positive and goodware corpus validation.
- [ ] Optional external collections with severity/confidence and update tracking.
- [ ] CI lint, build, test and independent review gates.
- [ ] Testing and production channels, timed promotion and telemetry alarm gates.
- [ ] Metrics for release frequency and operational throughput.

External TAC product deployment, customer instances, private corpora and production
telemetry require those systems to be available; do not report simulated checks as
production verification.

## Upstream synchronization

Both upstream branches were fetched on 2026-10-15. Upstream master at `83fde23`
(2026-08-12) is newer by commit date; rc at `d57fa30` (2025-07-08) has ten commits
absent from master, while master has three absent from rc. Both histories were
merged into this modernization branch. The personal fork's master was fast-forwarded
by 113 commits and its rc branch now matches upstream rc. No force pushes were used.
An idempotent migration adds the upstream ports column only when absent and never
drops externally maintained values on downgrade.

## Detection-as-code engine

The standalone threatkb_content package validates YAML/UUIDs, unique names and
pairings; renders bounded Jinja macro lists; derives category prefixes and rich
metadata; compiles dependencies; and verifies referenced SHA-256 samples/goodware.
Policy groups filter content before build. Sigpack, Feedpack and Codepack builds
are independent and carry manifests with file hashes and Git provenance. Optional
external collections require a pinned local Git checkout and remain separate
namespaces. Collection fetching is an explicit Git operation, never implicit code
execution. Testing-channel publication requires a review for the exact source
digest by someone other than its author. Production promotion requires an elapsed
observation window and recent complete telemetry without errors, alarms or an
excessive detection rate. Tests exercise both blocked and successful transitions.

These are local tooling and integration contracts. Deployment to TAC/customer
systems, production telemetry ingestion and the organization's release-frequency
outcome cannot be verified without those external systems. The code does not
fabricate those signals or automatically approve its own content.
