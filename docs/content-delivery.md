# CI and reviewed content delivery

The verification workflow has independent quality, application-test and matrix
Sigpack/Feedpack/Codepack jobs. Pack jobs have `fail-fast: false` and do not depend
on another pack or the application job. Successful manifests, checksummed ZIPs and
IOC assessments are retained for 30 days as GitHub workflow artifacts. The final
`verify` job runs even after a failure and requires all job results to succeed,
preserving the existing protected-branch status name.

Quality checks include Python correctness lint and formatting, TypeScript checking,
Prettier checks for frontend/YAML/workflows/Compose, shell syntax, and exact
age-evidence coverage for dependency/build locks and infrastructure pins. CI uses
the Docker `quality`, `verification` and standalone `content` targets; production
images do not contain test tools or compilers.

## Staged content hook

Enable the optional hook with `git config core.hooksPath .githooks`. It validates
the Git index snapshot, assigns UUIDs to staged `id: AUTO` placeholders, and checks
samples/goodware from the staged snapshot. It does not stage unrelated worktree
edits. Validation failure leaves the index unchanged. UUID replacement preserves
comments and other unstaged text. For a separate content repository, install the
Python package/tooling and adapt the hook's repository root and Python path.

## GitHub testing publication

`content-release.yml` is complete but opt-in. Set the repository Actions variable
`CONTENT_RELEASES_ENABLED=true` after reviewing the publisher and selecting the
intended public/private content repository. It runs on reviewed merges to master
that change content/tooling, or a manual dispatch on master. Manual dispatch can
select a configured group. Each pack builds and publishes independently.

Before an external write, `scripts.publish_content` requires:

1. An exact clean checkout matching `GITHUB_SHA`, with matching manifest provenance.
2. Correct archive checksums and no extra/unlisted archive members.
3. A merged PR into the release branch whose merge SHA is the release commit.
4. Approval of the final PR head by another human; self/bot/stale/dismissed approval
   and outstanding change requests are rejected.
5. The group's optional `github_reviewers` allowlist and successful validation.

A testing prerelease is staged as a draft, receives `pack.zip`, `manifest.json` and
`testing.json`, and becomes visible only after all uploads succeed. The tag binds
kind, group and full commit SHA. Retries reuse a matching release; an incomplete or
mislabeled published release fails rather than being reported successful. The
embedded review records the actual GitHub PR/reviewer and content digest. Local
web review policies continue to use `reviewers` with local analyst IDs.

The publisher does not submit telemetry or mark anything production. Existing
local testing/production channel commands remain available. Promotion freezes the
reviewed wait/consumer/rate policy at testing publication, records blocking reasons,
and exposes telemetry alarms in the workbench and scoped in-app notifications.
Clearing a notification does not clear the underlying channel alarm. A later
successful check/promotion resolves it.

This PR does not enable remote publication, create GitHub releases, send messages,
or connect external consumers. Tests replace the GitHub boundary while building
real packs and exercise denied publication, upload completion and idempotency.
Activation and a real independently approved merge still need operational acceptance.
The generic pack format is a local contract; proprietary TAC packaging belongs in
private adapters, and receiving systems must verify compatibility before cutover.
