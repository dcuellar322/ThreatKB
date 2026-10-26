# Database, correctness, and interface review — October 2026

Reviewed the Flask routes, models and shared helpers, workers, detection-content engine, migrations, React application, and existing tests. Changes extend the modernization PR; they preserve legacy APIs while repairing their behavior. This review is not a claim that arbitrary future inputs cannot reveal another defect.

## Measured database and runtime changes

Measurements use the same main local MySQL database: approximately 2,500 signatures, 10,000 IPs, 5,000 domains, and 400 tasks. Browser mutation tests use a separate database, content repository, and Redis queue. SQLAlchemy execution events count actual SQL statements. The final run records one cold request and four warm requests per endpoint; final timings below are warm medians. The baseline has one warm sample, so timings are indicative local measurements, not a load-test SLA.

| Request | SQL statements before → after | Warm time before → after |
|---|---:|---:|
| Signatures, 25 rows | 203 → 9 | 915 → 37 ms |
| IPs, 25 rows | 128 → 8 | 444 → 40 ms |
| Domains, 25 rows | 128 → 8 | 379 → 30 ms |
| Tasks, 25 rows | 28 → 6 | 86 → 19 ms |
| State counts | 26 → 6 | 129 → 42 ms |
| Global search | 184 → 28 | 638 → 91 ms |
| Git content overview | 1 → 1 | ~875 → 113 ms |

See `performance-before.json` and `performance-after.json` for all 13 measured endpoints. Artifact lists fetch related users, tags, metadata definitions/choices/values and optional comments for the current page. Empty caches are valid and no longer cause per-row fallback queries. Dashboard/state/category counts use grouped queries. Listing releases defers compressed payloads, and release generation decodes each payload once, selects latest staging revisions in one window query, batches release-history lookups, and uses set membership for comparisons.

A second bottleneck was macro expansion during validation, source exports, and scanning: 50 actual signatures required **101 SQL statements / 332 ms** with the previous implementation, versus **1 SQL statement / 6 ms** with a request-local macro snapshot. Active-rule compilation now uses a bounded cache keyed by the actual rule source and macro snapshot; content or macro changes invalidate the key. Analyst scans use their permitted rules. Git content parsing, source digests, and bounded template renders are also reused with filesystem-change checks.

Indexes cover both legacy creation-time ordering and workbench updated-time ordering: `(active, date, id)`, `(active, state, date, id)`, and `(owner_user_id, active, date, id)` for all four artifact tables. Related-data indexes cover comments, activity, metadata values, tags in both directions, bookmarks, revisions, tests, jobs and files. MySQL EXPLAIN verified ordered covering index access for active, state-filtered and owner-filtered requests. User joins before LIMIT previously produced hash joins, a large temporary table, and filesort; page serializers now supply cached users without those joins.

Substring search retains its original semantics. A normal B-tree does not accelerate arbitrary `%substring%` matches; the implementation bounds pages and filters and uses EXISTS rather than multiplicative joins. Full-text search would change matching behavior and is not substituted silently.

## Correctness fixes

- Multiple metadata filters, negative tags/comments, empty values, and structured filter operations now compose correctly without duplicate rows. Text search combines with advanced filters; it cannot overwrite a name filter. Sorting validates identifiers, includes a stable ID tie-breaker, and supports owner and metadata columns. Test-history sorting no longer interpolates SQL text.
- Bulk signature changes are atomic, preserve UUID/EventID, create revision snapshots and audit comments, and support unassignment and clearing descriptions. Bulk deactivation is consistent across artifact types. Signature merging renames exact identifier tokens, preserves quoted text and comments, scopes `them`, validates the result, and actually updates the destination when merging into an existing signature.
- Shared authorization now covers related files, comments, bookmarks, searches, tests and jobs. Global purge requires an administrator. Private policy groups cannot be accessed through the generic job or build-download endpoints. Non-admin imports and signature saves cannot enter a release state.
- File downloads have a working route. Upload hashes are streamed once; identical bytes under different filenames remain downloadable. Extracted symlinks are skipped. Path deletion is scoped to the artifact and complete directory components. Parent SHA-1 columns retain all 40 characters. Permanent signature deletion removes dependent test results and schedules in foreign-key order and refuses to erase history used by a published release.
- Script creation returns the newly created script and quoted arguments remain intact. Settings, macro snapshots, whitelist and state caches invalidate on changes. Empty configuration commits are harmless. Referenced states and categories cannot be renamed/deleted into orphaned artifact or release-history states. Revoked API keys cannot be reactivated. Validation/conflict errors return useful JSON without exposing database details.
- Route registration uses explicit module imports, avoiding wildcard namespace collisions. Mutable default arguments and an undefined legacy placeholder were removed. The frontend is split into page components and shared helpers, with unused declarations checked by TypeScript.

## Interface and browser verification

The initial screenshot showed oversized headers, tall rows, repeated UUIDs and a green palette. The workbench now uses black, white and red, compact table rows, sticky headers, persistent filters/columns/page sizes, explicit sort controls, range/page totals, and selected-row actions. Full-screen record dialogs keep actions visible while editing. Code fields have stable accessible names; state/owner selectors retain current values while definitions load. Mobile controls wrap into usable rows, tables scroll horizontally, and dialogs fit a 390-pixel viewport. Notices do not block controls beneath them. Extra promotional copy was removed.

Real-browser checks used an isolated MySQL database, an independent Git content repository, and a dedicated Celery/Redis queue. They exercised:

| Area | Actions verified |
|---|---|
| Tables | Page size, next/previous/jump, text search, state/advanced filters, prefix filter, AND/OR toggle, filter removal, ascending/descending sort, column hiding/restoration, selection and bulk edits |
| Signatures | Create/edit, source, export/download/copy, merge preview/import, merge into another signature, revision comparison/restore, follow/unfollow, confidence scheduling/cancellation, dirty-close acceptance/cancellation, full-screen toggle |
| Indicators/tasks | IPv6/ASN/country, domain match type, final artifact, create/edit/deactivate/restore; permanent signature/IP/domain purge |
| Samples | Upload/download/delete, sample/goodware jobs and completion, outcomes refresh, include-never-matched toggle, scan, candidate generation/import |
| Configuration | Create/edit for metadata, tags, macros, users, settings, whitelist, states, categories, scripts and source monitors; deletion for all applicable definitions; scripts executed with quoted arguments |
| Imports/releases | Extraction preview and selected commit, MISP warninglist, test release creation, notes/archive download, release deletion |
| Git content | Search, YAML edit/validation/commit, new draft, repository config commit, queued validation and Sigpack build, job details/completion, build archive download, review/testing/production gate feedback |
| Shell/account | Global search/deep link, notifications/clear, activity period/search/distribution, API key create/disable/enable/revoke, password change and subsequent login, logout/login, analyst navigation/ownership scoping, mobile navigation/table/editor |

Production promotion remains gated by independent review, telemetry and the required observation period. Browser QA exercised gate feedback; automated release-gate tests cover successful promotion and elapsed-time cases without waiting in real time. Local destructive checks never targeted the main development database. External DFI remains opt-in as previously agreed.

The automated suite includes regression tests for query counts, filters/pagination, exact-token merging, bulk revision history, related-resource authorization, MITRE persistence, scripts, duplicate-byte uploads, release-generation query bounds, key revocation, dependent-row purge, macro query bounds/cache reuse and test-history sort validation.
