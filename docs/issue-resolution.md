# Upstream issue verification

The fork has issue tracking disabled. The 40 open upstream issues are preserved in
`upstream-issues.json`. Each entry below records local evidence; upstream issues are
not automatically closed, and unlisted issues remain outstanding.

| Issue | Resolution and evidence |
| --- | --- |
| #508 | Fail-fast container entrypoint, explicit database configuration, recovered admin CLI. Full historical migrations reached head on a fresh MySQL 26.7.0 database; restored existing database also reports head. `test_entrypoint_stops_when_migration_fails` verifies failure prevents server startup. |
