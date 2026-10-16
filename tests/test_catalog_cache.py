import importlib
import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from app import app
from threatkb_content.engine import ContentError, Repository
from threatkb_content.catalog import CatalogCache

routes = importlib.import_module("app.routes.content")


def rule(root, name="First", **values):
    path = root / "rules" / f"{name}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    value = {
        "id": str(uuid4()),
        "name": name,
        "category": "UC",
        "strings": "",
        "condition": "false",
        **values,
    }
    path.write_text(yaml.safe_dump(value))
    return path


def cached(root, store_path):
    store = CatalogCache(store_path, root, routes.file_inventory(root))
    try:
        repo = Repository(root, rule_loader=store.load)
        store.finish()
        return repo
    finally:
        store.close()


def test_cold_cache_reuses_only_unchanged_validated_rules(tmp_path, monkeypatch):
    import threatkb_content.catalog as catalog

    root = tmp_path / "source"
    first = rule(root)
    second = rule(root, "Second")
    path = tmp_path / "cache/catalog.sqlite3"
    original = cached(root, path)
    calls = []
    real_load = catalog.load_rule

    def tracked(path):
        calls.append(path.name)
        return real_load(path)

    monkeypatch.setattr(catalog, "load_rule", tracked)
    assert cached(root, path).rules == original.rules
    assert calls == []
    second.write_text(second.read_text().replace("name: Second", "name: Edited"))
    updated = cached(root, path)
    assert calls == [second.name]
    assert [r["name"] for r in updated.rules] == ["First", "Edited"]
    first.unlink()
    assert len(cached(root, path).rules) == 1
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT name FROM rules").fetchall() == [
            ("rules/Second.yaml",)
        ]


def test_changed_policy_and_schema_are_not_hidden_by_cached_rules(
    tmp_path, monkeypatch
):
    import threatkb_content.catalog as catalog

    root = tmp_path / "source"
    rule(root)
    path = tmp_path / "cache/catalog.sqlite3"
    cached(root, path)
    (root / "categories.yaml").write_text("OTHER: Other\n")
    with pytest.raises(ContentError, match="Unknown category"):
        cached(root, path)
    (root / "categories.yaml").unlink()
    monkeypatch.setattr(catalog, "FORMAT", "new-loader-or-schema")

    def reject(path):
        raise ContentError("Revalidated after format change")

    monkeypatch.setattr(catalog, "load_rule", reject)
    with pytest.raises(ContentError, match="Revalidated"):
        cached(root, path)


def test_corrupt_rows_and_broken_database_fall_back_to_source(tmp_path):
    root = tmp_path / "source"
    rule(root)
    path = tmp_path / "cache/catalog.sqlite3"
    expected = cached(root, path).rules
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE rules SET value = ?", [json.dumps({"name": "Corrupt"})]
        )
    assert cached(root, path).rules == expected
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE rules SET value = ?", [sqlite3.Binary(b"bad encoded value")]
        )
    assert cached(root, path).rules == expected
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    path.write_bytes(b"broken sqlite file")
    assert cached(root, path).rules == expected


def test_cache_is_optional_and_never_written_into_content(tmp_path, monkeypatch):
    root = tmp_path / "source"
    rule(root)
    inside = root / "cache/catalog.sqlite3"
    assert cached(root, inside).rules
    assert not inside.exists()

    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("read-only cache")

    monkeypatch.setattr(sqlite3, "connect", unavailable)
    assert cached(root, tmp_path / "cache/catalog.sqlite3").rules


def test_yaml_dates_keep_their_original_types(tmp_path):
    from datetime import date

    root = tmp_path / "source"
    rule(root, metadata={"authored": date(2026, 1, 1)})
    path = tmp_path / "cache/catalog.sqlite3"
    assert cached(root, path).rules[0]["metadata"]["authored"] == date(2026, 1, 1)
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == 0


def test_release_repository_does_not_use_the_display_cache(tmp_path):
    root = tmp_path / "source"
    target = rule(root)
    path = tmp_path / "cache/catalog.sqlite3"
    cached(root, path)
    target.write_text(target.read_text().replace("name: First", "name: 42"))
    from jsonschema.exceptions import ValidationError

    with pytest.raises(ValidationError):
        Repository(root)
    with pytest.raises(ValidationError):
        cached(root, path)


def test_web_catalog_survives_process_cache_reset_and_detects_edits(
    authenticated, monkeypatch, tmp_path, content_save
):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    created = content_save("/ThreatKB/content/rules", {"name": "PersistentFixture"})
    initial = authenticated.get("/ThreatKB/content").json
    routes.invalidate_repository()
    import threatkb_content.catalog as catalog

    real_load = catalog.load_rule

    def unexpected(path):
        raise AssertionError("Process cold start must reuse validated rules")

    monkeypatch.setattr(catalog, "load_rule", unexpected)
    loaded = authenticated.get("/ThreatKB/content").json
    assert loaded["data"] == initial["data"]
    assert loaded["revision"] == initial["revision"]
    assert (
        authenticated.get("/ThreatKB/content/rules/" + created["id"]).json["yaml"]
        == created["yaml"]
    )
    monkeypatch.setattr(catalog, "load_rule", real_load)
    target = root / "rules" / created["file_name"]
    target.write_text(
        target.read_text().replace("name: PersistentFixture", "name: UpdatedFixture")
    )
    changed = authenticated.get("/ThreatKB/content?q=UpdatedFixture").json
    assert changed["data"][0]["name"] == "UpdatedFixture"
    assert changed["revision"] != initial["revision"]


def test_cold_catalog_reuses_digest_but_checks_external_inputs(
    authenticated, monkeypatch, tmp_path, content_save
):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    content_save("/ThreatKB/content/rules", {"name": "DigestFixture"})
    expected = authenticated.get("/ThreatKB/content").json["source_digest"]
    routes.invalidate_repository()
    routes._git_cache.clear()
    real_digest = Repository.digest

    def unexpected(repo):
        raise AssertionError("A cold display cache must not reread every source file")

    with monkeypatch.context() as context:
        context.setattr(Repository, "digest", unexpected)
        loaded = authenticated.get("/ThreatKB/content").json
        assert loaded["source_digest"] == expected
    # A non-rule input must invalidate the persisted digest, including on restart.
    (root / "observations.json").write_text('["external source"]')
    routes.invalidate_repository()
    changed = authenticated.get("/ThreatKB/content").json
    assert changed["source_digest"] != expected
    assert changed["source_digest"] == real_digest(Repository(root))


def test_busy_cache_falls_back_without_blocking_source_reads(tmp_path):
    root = tmp_path / "source"
    rule(root)
    path = tmp_path / "cache/catalog.sqlite3"
    expected = cached(root, path).rules
    with sqlite3.connect(path) as writer:
        writer.execute("BEGIN EXCLUSIVE")
        assert cached(root, path).rules == expected


def test_concurrent_edit_is_not_published_as_a_stable_catalog(
    authenticated, monkeypatch, tmp_path
):
    import threatkb_content.catalog as catalog

    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    routes.repository()
    target = rule(root)
    original = catalog.load_rule
    changed = False

    def edit_after_read(path):
        nonlocal changed
        value = original(path)
        if not changed:
            changed = True
            target.write_text(
                target.read_text().replace("condition: 'false'", "condition: 'true'")
            )
        return value

    monkeypatch.setattr(catalog, "load_rule", edit_after_read)
    assert authenticated.get("/ThreatKB/content").status_code == 409
    response = authenticated.get("/ThreatKB/content")
    assert response.status_code == 200
    assert response.json["data"][0]["condition"] == "true"


def test_catalog_prewarm_command_keeps_content_git_unchanged(
    client, monkeypatch, tmp_path
):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    routes.repository()
    rule(root)
    before = routes.git("rev-parse", "HEAD")
    result = app.test_cli_runner().invoke(args=["warm-content-catalog"])
    assert result.exit_code == 0, result.output
    assert "1 signatures" in result.output
    assert routes.git("rev-parse", "HEAD") == before
    assert "content-catalogs" not in routes.git("status", "--porcelain")
