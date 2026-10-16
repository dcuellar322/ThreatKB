# Dependency and build-input policy

Application, development and Python build-tool releases must be stable and at
least ten days old. The 2026-10-15 refresh uses the conservative cutoff
**2026-10-05 00:00:00 UTC**. The Python resolver produced the same eligible
application versions; no package downgrade or forced incompatible upgrade was
needed. Runtime, development/test, and wheel-build dependencies have separate
locks: `requirements.txt`, `requirements-dev.txt`, and `requirements-build.txt`.

```sh
uv pip compile requirements.in --python-version 3.14 --exclude-newer 2026-10-05T00:00:00Z --upgrade -o requirements.txt
uv pip compile requirements-dev.in --python-version 3.14 --exclude-newer 2026-10-05T00:00:00Z --upgrade -o requirements-dev.txt
uv pip compile requirements-build.in --python-version 3.14 --exclude-newer 2026-10-05T00:00:00Z --upgrade -o requirements-build.txt
.venv/bin/python scripts/audit_dependencies.py --as-of 2026-10-15
.venv/bin/python scripts/audit_dependencies.py --offline --as-of 2026-10-15
```

The online command queries PyPI/npm and records publication times. `--check` checks
without rewriting evidence. `--offline` verifies exact lock coverage and ages
against the recorded evidence, and is suitable for reproducible CI. Omitting
`--as-of` uses today's UTC date. A release exactly at the cutoff is allowed; a
release one second later is rejected. A minimum age below ten days is rejected.
All npm lock entries, including optional platform packages and integrity hashes,
are checked. Evidence covers the union of all three Python locks.

Docker bases and Compose services use immutable manifest digests. The Node
26.10 image was too recent and is replaced with the eligible Node 26.9 image.
MySQL remains 26.7.0 and Redis remains 8.10.2; their selected September builds avoid
October rebuilds of those same software tags. Python remains 3.14.7. Official
registry/image-history references, dates and pins are in
`infrastructure-dependency-audit.json`. GitHub actions use audited commit SHAs.

Debian indexes in the image are frozen at the same cutoff using
[snapshot.debian.org](https://snapshot.debian.org/). Compiler/wheel-build tools stay
in a builder stage, and build isolation cannot silently fetch newer unpinned
backends. The default production image excludes pytest, Ruff and compiler tools;
use the `verification` target for tests. The `content` target builds without Node,
MySQL or Redis services.

To refresh, advance the cutoff deliberately, resolve both ecosystems, select and
verify eligible immutable images/actions, update the Debian snapshot and registry
evidence, and run the age checker and CI. Do not update a mutable tag while leaving
its old evidence. Host-installed Docker, uv, Node and GitHub's hosted-runner OS are
execution tools outside these application/image locks; their versions are not
claimed to satisfy this project's release-age policy.

Intel macOS source builds additionally use pinned maturin/cffi backends and the
Rust 1.97.1 toolchain (released 2026-07-16). The combined evidence now covers
72 Python distributions, 87 npm distributions, and seven infrastructure/toolchain
records. A fresh installer must build successfully without relying on the original
virtual environment. See the native prerequisites in the local guide.
