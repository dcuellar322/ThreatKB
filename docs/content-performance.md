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
| Create or save a signature | Validate YAML/schema and enabled YARA, stage the changed file and commit as the analyst | Synchronous request under a repository lock |
| Save repository settings or record review | Validate the corresponding YAML/content definition and commit it | Synchronous request under the same lock |
| Validate content or build a pack | Check samples/goodware or produce a checked artifact | Celery worker, Redis queue, HTTP 202 with a durable job ID |
| Check automatic promotion | Apply review, elapsed-time and telemetry gates | Scheduled Celery task |

A new, uninitialized local content repository receives one bootstrap commit on
first access. Subsequent reads create no commits. Explicit saves reject an already
dirty worktree, commit only the intended file, and restore the file/index on failure.
Save success means validation and the local commit have finished. Validation and
build progress/results remain available through Background jobs.

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

Saving still includes parsing and compilation in the web request. This can take
seconds for a large repository. If editing throughput or cold catalog loading
becomes the next bottleneck, worker-maintained catalog snapshots and queued save
validation are the next scaling options. A queued save would need an expected
source revision checked inside the Git lock, rechecked analyst permissions, and
clear pending/failed/completed UI state before reporting a successful commit.
Those save semantics have not changed in this optimization.

## Verification

All **111 backend/content tests** pass locally. New regressions cover cached reads
without Git/hash work, external source and index changes, same-size edits, linked
files, Git worktree commits and literal/Jinja output equivalence. Frontend type
checking/build, formatting/lint, shell syntax and the dependency-age gate pass.

The Chromium check uses the rebuilt frontend, verifies initial pagination,
search/reset, YAML editor/history, unchanged Git HEAD across read workflows, and
HTTP 202 followed by a successful real worker validation. No JavaScript or console
errors were observed. Generated evidence is under ignored
`output/playwright/maintenance-2026-10-15/content-performance-after.png` and
`content-performance-results.json` on the development machine.
