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
or changed signature still needs full catalog parsing; observed cold profiles
were around two seconds after the changes. It is not a constant-time cold path.

Previously every filter/page request performed two Git subprocesses, walked the
source tree for a digest check, and separately scanned rule metadata. The read
path now takes one file inventory and reuses Git/digest results when unchanged.
It still checks file metadata on every request. External edits, additions,
deletions, mode changes, staging and commits invalidate the relevant cache.
Change times also detect same-size edits whose modification times were restored;
linked-file targets and Git worktree refs are accounted for. Caches are bounded
to the current repository and local to each web process.

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
time. Cold catalog reads remain synchronous and can still take seconds. Review
recording and explicit legacy exports remain synchronous. No action pushes local
content commits to a remote.

## Verification

All **122 backend/content tests** pass locally. Queued-save regressions cover
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
