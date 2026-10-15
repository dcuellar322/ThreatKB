import importlib
import json
import os
import subprocess

from app import app
from threatkb_content.engine import Repository

routes = importlib.import_module("app.routes.content")


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_search_and_pagination_reuse_metadata_without_creating_commits(
    authenticated, monkeypatch, tmp_path
):
    root = tmp_path / "content"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    authenticated.get("/ThreatKB/content")
    for name in ("First", "Second"):
        assert (
            authenticated.post(
                "/ThreatKB/content/rules", json={"name": name}
            ).status_code
            == 201
        )
    first = authenticated.get("/ThreatKB/content").json
    head = git(root, "rev-parse", "HEAD")

    def unexpected(*args):
        raise AssertionError("Unchanged page reads must not run Git or hash content")

    monkeypatch.setattr(routes, "git", unexpected)
    monkeypatch.setattr(routes.repository(), "digest", unexpected)
    searched = authenticated.get("/ThreatKB/content?q=Second").json
    assert searched["total_count"] == 1 and searched["data"][0]["name"] == "Second"
    page = authenticated.get("/ThreatKB/content?offset=1&limit=1").json
    assert len(page["data"]) == 1 and page["total_count"] == 2
    assert page["source_digest"] == first["source_digest"]
    assert page["git_commit"] == head == git(root, "rev-parse", "HEAD")


def test_external_edits_staging_and_commits_invalidate_read_metadata(
    authenticated, monkeypatch, tmp_path
):
    root = tmp_path / "content"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    initial = authenticated.get("/ThreatKB/content").json
    assert initial["git_status"] == ""
    path = root / "intelligence/observations.json"
    path.parent.mkdir()
    path.write_text(json.dumps(["first"]))
    changed = authenticated.get("/ThreatKB/content").json
    assert changed["source_digest"] != initial["source_digest"]
    assert "intelligence/" in changed["git_status"]
    before = path.stat()
    path.write_text(json.dumps(["other"]))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    edited = authenticated.get("/ThreatKB/content").json
    assert edited["source_digest"] != changed["source_digest"]
    assert edited["source_digest"] == Repository(root).digest()
    git(root, "add", "intelligence/observations.json")
    staged = authenticated.get("/ThreatKB/content").json
    assert staged["git_status"].startswith("A  intelligence/")
    assert staged["git_commit"] == initial["git_commit"]
    git(
        root,
        "-c",
        "user.name=External",
        "-c",
        "user.email=external@example.test",
        "commit",
        "-m",
        "External content",
    )
    committed = authenticated.get("/ThreatKB/content").json
    assert committed["git_commit"] != initial["git_commit"]
    assert committed["git_status"] == ""


def test_external_same_size_rule_edit_refreshes_the_rule_catalog(
    authenticated, monkeypatch, tmp_path
):
    root = tmp_path / "content"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    authenticated.get("/ThreatKB/content")
    created = authenticated.post("/ThreatKB/content/rules", json={"name": "First"}).json
    original = authenticated.get("/ThreatKB/content").json
    path = root / "rules" / (created["id"] + ".yaml")
    info = path.stat()
    path.write_text(path.read_text().replace("name: First", "name: Other"))
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    response = authenticated.get("/ThreatKB/content?q=Other").json
    assert response["data"][0]["name"] == "Other"
    assert response["source_digest"] != original["source_digest"]
    assert response["git_status"]
    target = tmp_path / "linked-rule.yaml"
    path.replace(target)
    path.symlink_to(target)
    authenticated.get("/ThreatKB/content")
    target.write_text(target.read_text().replace("name: Other", "name: Third"))
    assert (
        authenticated.get("/ThreatKB/content?q=Third").json["data"][0]["name"]
        == "Third"
    )


def test_worktree_head_changes_invalidate_metadata_without_source_changes(
    authenticated, monkeypatch, tmp_path
):
    root = tmp_path / "repository"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    authenticated.get("/ThreatKB/content")
    worktree = tmp_path / "worktree"
    git(root, "worktree", "add", "-b", "preview", str(worktree))
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(worktree))
    before = authenticated.get("/ThreatKB/content").json
    git(
        worktree,
        "-c",
        "user.name=External",
        "-c",
        "user.email=external@example.test",
        "commit",
        "--allow-empty",
        "-m",
        "Commit without content edits",
    )
    after = authenticated.get("/ThreatKB/content").json
    assert before["source_digest"] == after["source_digest"]
    assert before["git_commit"] != after["git_commit"]
