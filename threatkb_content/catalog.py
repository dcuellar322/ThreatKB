"""Disposable per-file cache for web catalog reads, never release validation.

The database lives outside the content repository. A fresh Repository still loads
policy/category/pairing definitions and checks cross-rule constraints; this loader
only reuses individual rules already parsed and schema-validated at identical file
fingerprints. Authoritative validation/build/save paths use the default loader.
"""

from hashlib import sha256
from importlib.metadata import version
from contextlib import suppress
import json
from pathlib import Path
import sqlite3

import yaml

from threatkb_content.engine import RULE_SCHEMA, load_rule

# Bump when the custom YAML loader, rule interpretation, or digest format changes.
CACHE_VERSION = "1"
FORMAT = sha256(
    json.dumps(
        [CACHE_VERSION, RULE_SCHEMA, yaml.__version__, version("jsonschema")],
        sort_keys=True,
    ).encode()
).hexdigest()


class CatalogCache:
    def __init__(self, path, root, inventory):
        self.path = Path(path)
        self.root = Path(root)
        self.fingerprints = {
            name: json.dumps([FORMAT, *entry])
            for name, *entry in inventory
            if name.startswith("rules/")
            and name.count("/") == 1
            and name.endswith(".yaml")
        }
        self.rows = {}
        self.pending = []
        self.pending_digest = None
        self.connection = None
        if self.path.resolve().is_relative_to(self.root.resolve()):
            return  # Cache files must never enter source digests or Git commits.
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.path.parent.chmod(0o700)
            self.connection = sqlite3.connect(self.path, timeout=0.05)
            self.path.chmod(0o600)
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS rules (name TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, value TEXT NOT NULL, checksum TEXT NOT NULL)"
            )
            self.connection.execute(
                "CREATE TABLE IF NOT EXISTS digests (id INTEGER PRIMARY KEY CHECK (id = 1), fingerprint TEXT NOT NULL, value TEXT NOT NULL, checksum TEXT NOT NULL)"
            )
            self.rows = {
                name: (fingerprint, value, checksum)
                for name, fingerprint, value, checksum in self.connection.execute(
                    "SELECT name, fingerprint, value, checksum FROM rules"
                ).fetchall()
            }
        except OSError, sqlite3.Error:
            self.close()

    def load(self, path):
        # Repository invokes this only for immediate rules/*.yaml children.
        name = "rules/" + path.name
        fingerprint = self.fingerprints.get(name)
        cached = self.rows.get(name)
        if (
            cached
            and cached[0] == fingerprint
            and all(isinstance(item, str) for item in cached)
        ):
            encoded, checksum = cached[1:]
            if sha256(encoded.encode()).hexdigest() == checksum:
                try:
                    rule = json.loads(encoded)
                    if isinstance(rule, dict):
                        return rule
                except ValueError, TypeError:
                    pass
        rule = load_rule(path)
        if self.connection is None:
            return rule
        # Preserve YAML-only types (e.g. dates), rather than changing their meaning
        # through JSON coercion. Such files simply use the source loader each time.
        try:
            encoded = json.dumps(rule, ensure_ascii=False, allow_nan=False)
            if fingerprint is not None and json.loads(encoded) == rule:
                self.pending.append(
                    (name, fingerprint, encoded, sha256(encoded.encode()).hexdigest())
                )
        except ValueError, TypeError:
            pass
        return rule

    def digest(self, repo, inventory):
        sources = [
            entry
            for entry in inventory
            if entry[0] != "review.yaml"
            and entry[0].rsplit(".", 1)[-1]
            in ("yaml", "yml", "yar", "yara", "json", "csv")
        ]
        fingerprint = sha256(json.dumps([FORMAT, sources]).encode()).hexdigest()
        if self.connection is not None:
            try:
                row = self.connection.execute(
                    "SELECT fingerprint, value, checksum FROM digests WHERE id = 1"
                ).fetchone()
                if (
                    row
                    and all(isinstance(item, str) for item in row)
                    and row[0] == fingerprint
                    and row[2] == sha256(row[1].encode()).hexdigest()
                ):
                    if len(row[1]) == 64 and all(
                        c in "0123456789abcdef" for c in row[1]
                    ):
                        return row[1]
            except sqlite3.Error:
                pass
        value = repo.digest()
        self.pending_digest = (fingerprint, value, sha256(value.encode()).hexdigest())
        return value

    def finish(self):
        if self.connection is not None:
            try:
                self.connection.executemany(
                    "INSERT OR REPLACE INTO rules (name, fingerprint, value, checksum) VALUES (?, ?, ?, ?)",
                    self.pending,
                )
                self.connection.executemany(
                    "DELETE FROM rules WHERE name = ?",
                    [(name,) for name in self.rows if name not in self.fingerprints],
                )
                if self.pending_digest:
                    self.connection.execute(
                        "INSERT OR REPLACE INTO digests (id, fingerprint, value, checksum) VALUES (1, ?, ?, ?)",
                        self.pending_digest,
                    )
                self.connection.commit()
            except sqlite3.Error:
                # A read-only, full, corrupt, or busy cache must not break content.
                with suppress(sqlite3.Error):
                    self.connection.rollback()
        self.close()

    def close(self):
        if self.connection is not None:
            with suppress(sqlite3.Error):
                self.connection.close()
            self.connection = None
