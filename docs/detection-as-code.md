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
Repository maintainers must protect the release branch and require an independent
PR approval in their hosting system; a local file cannot replace host access policy.

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

The optional web editor validates and commits YAML edits into the configured
`CONTENT_REPOSITORY`; sample bytes are supplied by `CONTENT_CORPUS`. Defaults use
ignored development directories. Export legacy signatures from Configuration;
UUIDs already present are skipped. The legacy database remains available for IOC
and task workflows. Keep its backup and a Git snapshot of the content repository
before a cutover. A Git revert produces a new content revision and build; channels
then pass through the same testing gates. Historical manifests are immutable
records and should not be edited to manufacture a rollback.

External contracts still require integration at the receiving system: UUID-aware
TAC consumers, ten-minute channel polling, telemetry delivery, alert escalation,
and vendor DFI preprocessing. No TAC/customer endpoints, private collection
checkouts, production corpora or DFI image were available locally. The application
provides tested contracts and blocks promotion when required telemetry is missing.
