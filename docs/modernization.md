# ThreatKB modernization

The modernization branch runs Python 3.14.7, Flask 3, React and MySQL 26.7. It
preserves legacy management workflows while adding standalone detection and IOC
content tooling. [Design acceptance](design-acceptance.md) is the authoritative
implemented-versus-remaining matrix; local capabilities are not a claim of
completed customer deployment or organizational cutover.

## Upstream synchronization

Upstream master `83fde23` and rc `d57fa30` are both ancestors of
`codex/2026-modernization`. Master and rc had divergent commits and both histories
were merged. The fork's master was fast-forwarded by 113 commits and its rc branch
synchronized without force pushes. Forty currently open upstream issues have
recorded resolutions in [issue-resolution.md](issue-resolution.md), including the
approved DFI exception. They remain open upstream. The PR remains a draft for
independent review.

## Maintained capabilities

- Modern local/container startup, fail-fast migrations and administrator recovery.
- Preserved record, metadata, tag, revision, task, file, script, import and account
  workflows, with desktop/mobile browser evidence and permission checks.
- Git/YAML signatures, bounded macros, stable UUIDs, sample/goodware tests,
  pairings, policy groups and optional pinned external collections.
- Standalone IOC assessment/enrichment/review and independent content builders.
- Independent CI jobs, retained artifacts, formatting/lint/age checks, a staged
  content hook, and optional reviewed testing publication.
- Testing/production channel engine with review-bound policy, telemetry gates,
  persistent alarms, metrics and rollback through new builds.

Runtime, development, source-build and infrastructure inputs follow the
[ten-day policy](dependency-policy.md). Main local data and the original MySQL
snapshot are retained. DFI is disabled by agreement, and real consumer deployment,
private corpora/collections, external telemetry/escalation and measured release
frequency remain explicit acceptance items.

Read [local-development.md](local-development.md), [detection-as-code.md](detection-as-code.md),
[intelligence-pipeline.md](intelligence-pipeline.md), [content-delivery.md](content-delivery.md),
and [verification.md](verification.md) for commands and evidence.
