# Upstream issue verification

The fork has issue tracking disabled. The 40 open upstream issues are preserved in
`upstream-issues.json`. Each entry below records local evidence; upstream issues are
not automatically closed, and unlisted issues remain outstanding.

| Issue | Resolution and evidence |
| --- | --- |
| #508 | Fail-fast container entrypoint, explicit database configuration, recovered admin CLI. Full historical migrations reached head on a fresh MySQL 26.7.0 database; restored existing database also reports head. `test_entrypoint_stops_when_migration_fails` verifies failure prevents server startup. |
| #41 | Authenticated in-memory upload scanner returns YARA hits and matching string offsets/bytes, imposes upload and scan time limits, and retains no uploaded file. Verified with real YARA compilation and matching in `test_issue_41.py`. |
| #235 | Invalid/unknown logins return 401, malformed credentials return 400, anonymous error reporting is safe, and passwords are no longer logged. Verified with missing-user, bad-password and anonymous-exception requests. |
| #492 | Validate and canonicalize IPs before ingestion and on model insertion; invalid rows roll back without poisoning subsequent imports. Disabled whitelisting permits ingestion. Expanded storage to IPv6 length. Mixed invalid/valid batch regression passes. |
| #505 | EventID allocation locks the category row through the artifact transaction; the database enforces uniqueness even for explicitly imported IDs. Migration rejects preexisting duplicates with a clear report. Allocation/constraint tests pass and local MySQL migration succeeds. |
