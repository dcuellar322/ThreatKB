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
| #440 | Replaced regex YARA rule extraction with Plyara's syntax parser and raw section preservation. Imports commit rules and revision history, including the issue's certificate rule, inline rules, comments and literal braces. `test_issue_440.py` passes. |
| #487 | JSON ingestion accepts shared tags as strings or tag dictionaries and associates them with every imported rule. Rich machine tags survive round-trip; ingestion regression passes. |
| #113 | Persistent per-rule confidence schedule supports create/edit/cancel. A Celery beat task applies due changes once; a CLI command supports local/manual runs. UTC timestamp, range and ownership checks enforced. Due/application/cancellation regression passes. |
| #214 | Metadata definitions and enum choices are editable through PUT by ID. Removing a choice in use or converting incompatible stored values returns 409. Choice addition and data protection regressions pass. |
| #244 | Admins can deactivate users while preserving historical attribution. Deactivation releases ownership, revokes access keys, and invalidates existing sessions. Self-deactivation is prevented. Multi-session regression passes. |
| #273 | Replaced legacy shell bootstrap with fail-fast Python 3.14 installation, correctly exported optional .env, and modern server/worker launchers. Shell syntax checks and an actual local installation/migration run pass. Windows bootstrap also targets the same lock. |
