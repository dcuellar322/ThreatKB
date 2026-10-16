# Detection content without the web application

The `threatkb_content` package reads a plain Git repository. Flask, MySQL and Redis
are unnecessary for its CLI. `detections/` contains a harmless, public example;
`instance/dev-content` contains the much larger local synthetic repository. Do not
publish the latter or export real intelligence without reviewing its contents.

## Author, validate, build

```sh
.venv/bin/python -m threatkb_content --root detections ids
.venv/bin/python -m threatkb_content --root detections check --corpus detections/samples --goodware detections/goodware
.venv/bin/python -m threatkb_content --root detections build --kind sigpack --corpus detections/samples --goodware detections/goodware
.venv/bin/python -m threatkb_content --root detections build --kind feedpack
.venv/bin/python -m threatkb_content --root detections build --kind codepack
```

Rules use immutable UUIDs (`AUTO` requests assignment), a category code, name,
strings, condition, metadata, tags and a separate status. Category prefixes derive
from metadata, not EventID ranges. `references.public.samples` contains SHA-256
filenames in the corpus. `testing_strategy: [match_all_referenced_samples]` requires
each sample to match. Strict policy can require positive samples and goodware.
Existing EventIDs survive legacy export as metadata; legacy records acquire UUIDs
through a data migration. Renames and category changes retain their UUID.

`macros.yaml` stores Jinja values/lists. Filters include `regex_chunks`,
`alternation` and `yara_strings`; strict undefined variables, expansion limits and
compilation catch broken macros. `pairings.yaml` stores heater/cooler records with
`rule_ids` referencing UUIDs. Pack manifests include scoped pairings.

`collections.yaml` optionally names a locally checked-out Git repository, an exact
`revision`, an `enabled` flag, severity and confidence. Policies explicitly select
collections. Update that checkout and pinned revision in a reviewed Git change;
the build refuses a different checkout revision. External rules compile in their
own namespace. No untrusted collection scripts are executed.

`indicators.yaml` independently supplies released IP/domain records for Feedpack.
`components.yaml` supplies repository-relative software paths and SHA-256 hashes
for Codepack. Each pack has its own validation, manifest and ZIP; a broken internal
signature does not block Feedpack or Codepack. Production vendor-specific pack
formats can be implemented as consumers of these manifests.

## Review and release channels

A second analyst records `review.yaml` with distinct `author` and `reviewer` IDs
and the exact `source_digest` returned by validation. Group policy may restrict
reviewers. The web API derives the author from Git history and refuses self-review.
The fork master branch is protected with the verify status check, independent PR
approval, stale approval dismissal and approval after the last push, including for
administrators. Apply the same hosting policy to a separate content repository;
a local file cannot replace host access policy.

```sh
.venv/bin/python -m threatkb_content --root detections publish-testing instance/builds/BUILD_UUID/manifest.json
.venv/bin/python -m threatkb_content --root detections telemetry BUILD_UUID local report.json
.venv/bin/python -m threatkb_content --root detections promote
```

Reports contain timezone-aware `window_start`, `window_end`, nonnegative integer
`detections` and `errors`, plus optional `alarms`. Future/partial/stale reports,
missing consumers, errors, alarms and excessive rates block promotion. Default
observation is 30 minutes. Celery beat checks eligible testing releases each minute;
publication and promotion history is retained and repeat promotion is idempotent.
No synthetic telemetry is submitted to operational channels during development.
The API exposes monthly Sigpack release counts against the historical 4.5/month
baseline and 9/month target; achieving that outcome requires actual team usage.

CI builds the application, runs isolated regressions, and exercises all three pack
builders. Install the optional pre-commit hook with `git config core.hooksPath
.githooks`; it assigns UUID placeholders and validates the example repository.
Stage rule edits intentionally before committing. For a separate content repo,
copy/adapt the hook's root and Python executable paths.

## Migration, interfaces and rollback

The optional web editor queues validation and local Git commits for YAML edits in the configured
`CONTENT_REPOSITORY`; sample bytes are supplied by `CONTENT_CORPUS`. Defaults use
ignored development directories. Export legacy signatures from Configuration;
UUIDs already present are skipped. The legacy database remains available for IOC
and task workflows. Keep its backup and a Git snapshot of the content repository
before a cutover. A Git revert produces a new content revision and build; channels
then pass through the same testing gates. Historical manifests are immutable
records and should not be edited to manufacture a rollback.

External contracts still require integration at the receiving system: UUID-aware
TAC consumers, ten-minute channel polling, telemetry delivery and alert escalation.
Optional vendor DFI preprocessing is disabled by user choice. No TAC/customer
endpoints, private collection checkouts or production corpora were available locally. The application
provides tested contracts and blocks promotion when required telemetry is missing.

## Maintenance follow-up

The optional staged-content hook now validates the Git index snapshot and preserves
unrelated/unfinished worktree edits. CI jobs are independent, retain pack artifacts,
and enforce formatting and dependency ages. Reviewed GitHub testing publication is
implemented but requires explicit activation and a real approved merge; see
[content-delivery.md](content-delivery.md).

Repositories may opt into `intelligence/pipeline.yaml` for standalone provenance,
normalization, policy, local enrichment, review and quarantine before Feedpack
creation. Existing `indicators.yaml` exports remain the fallback. Raw CSV/JSON
inputs are included in the content digest. See [intelligence-pipeline.md](intelligence-pipeline.md).

Promotion freezes wait/consumer/rate policy at testing publication. Block reasons
persist in channel state; actual telemetry alarms appear in the workbench and in
notifications for authorized groups. Clearing notifications does not clear the
underlying alarm. Operational telemetry and external notification routing still
require their actual integrations.

## Web execution and performance

Page reads create no commits after initial repository bootstrap. Signature and
repository-settings saves return HTTP 202 with a durable Celery job; the editor
reports success only after validation and the local commit finish. Saves require
the editor's source revision and reject stale or conflicting changes. Validation
and build buttons also use Celery jobs. See
[content-performance.md](content-performance.md) for the execution boundaries,
cache invalidation, measured improvement, and remaining cold-read costs.
