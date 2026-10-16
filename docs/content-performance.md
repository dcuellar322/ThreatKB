# Detection-as-code execution and performance

The workbench uses a separate content Git repository, normally
`instance/dev-content` or the configured `CONTENT_REPOSITORY`. Its commits are
separate from commits to the ThreatKB application source repository. No web action
pushes these local commits to a remote.

## What runs when

| Action | Work | Execution |
|---|---|---|
| Open, search or paginate | Read YAML catalog, Git status, digest, manifests and channels | Browser fetch; synchronous Flask request with cached read metadata |
| Open a signature | Read YAML and the last ten Git history entries | Synchronous request; no commit |
| Create or save a signature, or save repository settings | Queue a revision-bound draft; validate YAML/schema and enabled YARA in a private copy, then commit as the analyst | HTTP 202; Celery worker under a repository lock |
| Record independent review | Validate the review definition and commit it | Synchronous request under the same lock |
| Validate content or build a pack | Check samples/goodware or produce a checked artifact | Celery worker, Redis queue, HTTP 202 with a durable job ID |
| Check automatic promotion | Apply review, elapsed-time and telemetry gates | Scheduled Celery task |

A new, uninitialized local content repository receives one bootstrap commit on
first access. Subsequent reads create no commits. Explicit saves reject an already
dirty worktree, commit only the intended file, and restore the file/index on failure.
A queued-save response is not a successful commit. The editor shows queued,
validating, failed, or committed state and the resulting commit ID. Failed saves
retain the draft, and a confirmed Reload latest action loads current source.
Continue in background releases the editor while the durable job continues; the
same browser tab restores the pending editor/job on a later visit or reload.
Pending drafts are scoped to the signed-in account in session storage. Save,
validation, and build results remain available through Background jobs.

## Measured improvement on 2026-10-15

Measurements use the local development repository containing **2,502 YAML
signatures**, the same machine/browser, and authenticated endpoint requests.

| Measurement | Before | After |
|---|---:|---:|
| Warm `/ThreatKB/content` median | 276 ms, six requests | 68 ms, eight requests |
| Warm endpoint range | 250–319 ms | 55–97 ms |
| Profiled warm handler, mean of four calls | 235 ms | 48 ms |
| Fixed browser delay on initial load/page/group/refresh | 250 ms | Removed |
| Click to rendered content controls | Not recorded | 118 ms |

This is local evidence, not a production latency guarantee. Browser search still
has a 250 ms debounce; other view changes request data immediately. A first load
or changed signature previously needed full catalog parsing; the persistent
catalog cache below replaces that behavior. Initial cache creation still parses
the complete repository. It is not a constant-time cold path.

Previously every filter/page request performed two Git subprocesses, walked the
source tree for a digest check, and separately scanned rule metadata. The read
path now takes one file inventory and reuses Git/digest results when unchanged.
It still checks file metadata on every request. External edits, additions,
deletions, mode changes, staging and commits invalidate the relevant cache.
Change times also detect same-size edits whose modification times were restored;
linked-file targets and Git worktree refs are accounted for. In-memory caches are
bounded to the current repository in each web process; the catalog cache below
is shared through the persistent instance workspace.

Read-only Git status uses `--no-optional-locks` to avoid refreshing the Git index.
Build, review and promotion checks retain their own current source/digest checks;
the display cache is not an authorization or publication shortcut.

Plain YARA text also bypasses Jinja template compilation, while matching Jinja's
newline handling and output-size limit. Text with template delimiters keeps the
sandboxed macro path and its bounds. This reduces materialization work during
saves, validation and builds without changing pack output semantics.

## Worker boundaries

Normal page reads remain request/response operations. Queueing these reads would
add a queue and polling round trip to work now measured in tens of milliseconds.
The existing worker already handles full sample validation and pack construction.
The verified default-group validation job checked **1,250 selected rules and
positive samples plus 25 goodware samples**; selection policy excludes the other
catalog entries.

Signature creation, signature edits, and repository-settings saves now use the
existing `save_content` job handler. Their HTTP requests perform lightweight
access/revision checks without parsing or compiling the full catalog. The worker
validates a private snapshot, so invalid drafts never replace live source. It
checks the expected repository revision under the Git lock before validation and
again before committing, then refreshes the analyst's active status/permissions.
The final database check starts a fresh transaction to see revocations under
MySQL's repeatable-read isolation. Saves with competing commits or external edits
fail explicitly instead of overwriting newer work. A duplicate delivery of a
completed job cannot create another commit.

Editor GET responses provide `revision` and (for signatures) `file_name`.
`POST /ThreatKB/content/rules` and both content-editor `PUT` endpoints require the
revision; signature PUT also requires its returned filename. They return HTTP 202
with a durable job ID. Missing revisions return 428 and already-stale revisions
return 409. Validation errors and conflicts discovered after queueing are recorded
as failed jobs. Poll `/ThreatKB/jobs/<id>` for the completed result, including the
new revision, YAML, Git commit, and history. Direct generic-job submission of
`save_content` is rejected; only the authorized editor endpoints construct saves.
A broker outage returns 503 and does not modify content. No-op saves do not create
an extra commit. Reads still create no commits after repository bootstrap.

Full catalog parsing, snapshot copying, compilation, and the Git commit still take
worker time; queueing removes them from the save request, not from total elapsed
time. Catalog reads remain synchronous; unchanged rules and their source digest
are reused across restarts. An empty cache still needs its initial build. Review
recording and explicit legacy exports remain synchronous. No action pushes local
content commits to a remote.

## Persistent cold catalog cache

Catalog listing and signature-editor reads use a disposable SQLite cache under
`instance/content-catalogs/`, separated by the resolved content-repository path.
It stores parsed/schema-validated rules individually and the display source
digest. After a process restart, unchanged rules are loaded in one database read;
a changed rule is reparsed without reparsing the other signatures. Deleted rules
are removed from the cache. The catalog still checks duplicate identities/names,
category/group references, and pairings against current definitions.

Each entry is tied to file modification/change times, size, mode, and linked-file
target metadata. Parser/schema versions invalidate old entries; payload checksums
detect corrupted rows. Source inventory is checked again before publishing a new
catalog, so a concurrent edit returns an explicit conflict instead of presenting
a catalog assembled across revisions. Non-rule content inputs also invalidate
the persisted digest. External edits and Git status/revisions remain visible.

This cache is for web reads only. Worker saves, full validation, pack builds,
independent review, and release operations retain source validation. Publication gates do not consume cached validation results. Group membership
definitions come from current policy source, with file changes invalidating the
in-memory catalog. Group-only authorization no longer parses the full
signature catalog just to queue a job.

The cache directory is private (0700) and its databases are 0600. Missing,
corrupted, unavailable, read-only, or busy cache storage falls back to source
loading. YAML values that cannot round-trip through JSON, including dates, retain
their source types and bypass per-rule caching. Cache storage is disabled if its
configured location would fall inside the content repository, so derived files
cannot affect source digests or Git commits. Cache files are disposable and may
be removed when the app is stopped; the next read recreates usable storage.

The first-ever cache build still reads and validates all source files. Large
repositories can prepare it before opening the UI:

```sh
.venv/bin/flask --app app warm-content-catalog
# Or, against the shared container workspace:
docker compose exec web flask --app app warm-content-catalog
```

This command prepares the read cache, without committing content after the normal
initial repository bootstrap. It does not require a worker or Redis to serve
cached reads. Cache warmup is an optimization, not release approval.

## Cold-load measurements

On the local 2,503-signature catalog, authenticated requests with process caches
cleared before each request improved as follows (three requests per column):

| Run | Full source parsing median | Persistent catalog median |
|---|---:|---:|
| Development comparison | 4,229 ms | 563 ms |
| Concurrent full worker validation | 5,708 ms | 1,097 ms |

These runs show roughly **5–7.5× faster** cold-process reads. They retain the OS
filesystem cache and persisted catalog index; they do not measure an empty index.
Local CPU/I/O load varies, so these are development observations, not production
latency guarantees. The first cache build still parses source as described above.

In Chromium, the first catalog request after a fresh idle web-process restart
returned HTTP 200 in **702 ms**, with controls and rows rendered in **768 ms**.
Search, pagination, source/history, and a real worker save were exercised; the
new commit and edited YAML appeared without stale catalog data. Desktop/mobile
screenshots and measurements are stored under ignored
`output/playwright/maintenance-2026-10-15/cold-catalog-results.json`,
`content-cold-catalog.png`, and `content-catalog-mobile.png`.

## Verification

All **133 backend/content tests** pass locally. Persistent-cache coverage includes
cold reuse, invalidation, corruption/fallback, concurrent writes, value types,
prewarming, and independent source validation. Queued-save regressions cover
deferred work, stale/missing revisions, competing saves, unchanged live source
during failed compilation, external edits during validation, revoked account and
administrator access, queue outages, no-op commits, rollback, and duplicate task
delivery. Read-performance regressions cover cached reads
without Git/hash work, external source and index changes, same-size edits, linked
files, Git worktree commits and literal/Jinja output equivalence. Frontend type
checking/build, formatting/lint, shell syntax and the dependency-age gate pass.

The Chromium check uses the rebuilt frontend, verifies initial pagination,
search/reset, YAML editor/history, unchanged Git HEAD across read workflows, and
HTTP 202 followed by a successful real worker validation. No JavaScript or console
errors were observed. Generated evidence is under ignored
`output/playwright/maintenance-2026-10-15/content-performance-after.png` and
`content-performance-results.json` on the development machine.
