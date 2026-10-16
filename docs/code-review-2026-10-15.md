# Performance, correctness and interface review

This pass follows the user's report of slow queries and loss of the original
black/white/red interface. Review scope includes every application route, model,
service, standalone content module, CLI, deployment path and frontend component.
Review and verification are ongoing; this document records concrete findings.

## Measured findings

On the existing seeded MySQL workspace, a 25-row signature list used 203 SQL
statements (~915 ms warm); IP/domain lists used 128 each (~444/379 ms). Related
metadata, comments, tags and users were fetched separately for each row. State
counts executed 26 queries. Global search loaded whole-database caches and then
queried per-row history. The content listing reread thousands of YAML files for
its digest and traversed Git objects.

MySQL EXPLAIN showed table scans and filesorts for active/date-ordered artifact
lists. The new composite indexes use active/date, active/state/date and
owner/active/date prefixes. After migration these plans use ordered covering
index lookups. Related-data indexes match artifact, metadata, tag, bookmark,
history and job lookups. Leading-wildcard text searches cannot use a normal
B-tree seek; adding arbitrary indexes to text fields would not solve that cost.

## Correctness findings being addressed

- Metadata joins duplicated rows and could not match two independent fields.
- Comment filtering inverted matches and fell through into metadata handling.
- Negative tag filtering admitted records carrying both blocked and other tags.
- Nonunique sorting could repeat or skip records between pages.
- Missing pagination bounds admitted negative/oversized queries.
- Global search bypassed ownership visibility used by artifact endpoints.
- Whole-database caches caused stale and unnecessarily expensive search results.
- Content review digest exclusion also omitted rule files beginning with review.
- Further route, mutation, authorization and original-workflow review continues.

## Interface findings

The original screenshot is retained locally under output/playwright. The green
palette, promotional copy, oversized headers/rows and repeated UUIDs reduced
information density. Sorting and useful column filters were absent; page controls
fell below a long document. Profile clicks signed out accidentally. Dialogs omitted
original fields/actions and could discard edits. These are functional and usability
issues, not a request for more decorative dashboard content.

The replacement uses black/white/red, compact work tables, explicit sorting and
filters, sticky headers/pagination, concise labels and complete artifact actions.
Original bulk edits, YARA export, copy/merge, revision comparison, references and
MITRE fields must remain available. Browser action results will be recorded after
implementation; untested actions are not counted as verified.
