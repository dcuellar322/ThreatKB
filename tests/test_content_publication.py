import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from scripts.publish_content import approval_for, publish
from threatkb_content.engine import ContentError, Repository

REPO = "example/threatkb"
SHA = "a" * 40
HEAD = "b" * 40


def pr(commit=SHA):
    return {
        "number": 1,
        "merged_at": datetime.now(timezone.utc).isoformat(),
        "merge_commit_sha": commit,
        "base": {"ref": "master", "repo": {"full_name": REPO}},
        "head": {"sha": HEAD},
        "user": {"login": "author"},
        "html_url": "https://github.com/example/threatkb/pull/1",
    }


def review(**extra):
    return {
        "state": "APPROVED",
        "commit_id": HEAD,
        "user": {"login": "reviewer", "type": "User"},
        "submitted_at": "2026-10-15T00:00:00Z",
        **extra,
    }


class Provider:
    def __init__(self, commit=SHA, reviews=None):
        self.pr = pr(commit)
        self.reviews = reviews if reviews is not None else [review()]
        self.releases = []
        self.writes = []
        self.uploads = []
        self.session = self

    def pages(self, path):
        if path.endswith("/pulls"):
            return iter([self.pr])
        if path.endswith("/reviews"):
            return iter(self.reviews)
        if path == "/releases":
            return iter(self.releases)
        raise AssertionError(path)

    def request(self, method, path, **kwargs):
        self.writes.append((method, path, kwargs))
        if method == "POST":
            value = {
                **kwargs["json"],
                "id": 1,
                "assets": [],
                "upload_url": f"https://uploads.github.com/repos/{REPO}/releases/1/assets{{?name,label}}",
                "html_url": "https://github.com/example/threatkb/releases/tag/testing",
            }
            self.releases.append(value)
            return value
        if method == "PATCH":
            self.releases[0].update(kwargs["json"])
            return self.releases[0]
        raise AssertionError((method, path))

    def post(self, url, params, data, **kwargs):
        self.uploads.append((params["name"], data.read()))
        self.releases[0]["assets"].append(
            {"id": len(self.uploads), "name": params["name"]}
        )
        return self

    def raise_for_status(self):
        pass


@pytest.mark.parametrize(
    "change", ["self", "stale", "dismissed", "changes-requested", "bot", "wrong-branch"]
)
def test_publication_requires_current_independent_human_approval(change):
    provider = Provider()
    if change == "self":
        provider.reviews = [review(user={"login": "AUTHOR", "type": "User"})]
    if change == "stale":
        provider.reviews = [review(commit_id="c" * 40)]
    if change == "dismissed":
        provider.reviews += [review(state="DISMISSED")]
    if change == "changes-requested":
        provider.reviews += [
            review(state="CHANGES_REQUESTED", user={"login": "other", "type": "User"})
        ]
    if change == "bot":
        provider.reviews = [review(user={"login": "automation", "type": "Bot"})]
    if change == "wrong-branch":
        provider.pr["base"]["ref"] = "unprotected"
    with pytest.raises(ContentError):
        approval_for(provider, REPO, SHA)
    assert provider.writes == []


def checkout(tmp_path):
    root = tmp_path / "repo"
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "detections", root / "detections"
    )

    def git(*args):
        return subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    git("init", "-b", "master")
    git("add", "detections")
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.test",
        "commit",
        "-m",
        "Reviewed content",
    )
    sha = git("rev-parse", "HEAD")
    repo = Repository(root / "detections", root / "detections/samples")
    manifest = repo.build(tmp_path / "builds", goodware=root / "detections/goodware")
    path = tmp_path / "builds" / manifest["id"] / "manifest.json"
    return root, sha, path


def test_reviewed_publication_uploads_complete_testing_artifact_and_is_idempotent(
    tmp_path,
):
    root, sha, path = checkout(tmp_path)
    provider = Provider(sha)
    value = publish(
        root / "detections", path, tmp_path / "publication", provider, REPO, sha
    )
    assert not value["draft"] and value["prerelease"]
    assert {name for name, _ in provider.uploads} == {
        "pack.zip",
        "manifest.json",
        "testing.json",
    }
    state = json.loads(dict(provider.uploads)["testing.json"])
    assert state["status"] == "testing" and state["telemetry"] == {}
    assert (
        state["review"]["provider"] == "github"
        and state["review"]["reviewer"] == "reviewer"
    )
    assert state["artifact_url"].endswith("/pack.zip")
    writes = copy.deepcopy(provider.writes)
    assert (
        publish(
            root / "detections", path, tmp_path / "publication", provider, REPO, sha
        )
        == value
    )
    assert provider.writes == writes


def test_unreviewed_and_tampered_archives_cannot_create_remote_release(tmp_path):
    root, sha, path = checkout(tmp_path)
    provider = Provider(sha, reviews=[])
    with pytest.raises(ContentError):
        publish(
            root / "detections", path, tmp_path / "publication", provider, REPO, sha
        )
    assert provider.writes == []
    provider.reviews = [review()]
    with zipfile.ZipFile(path.parent.with_suffix(".zip"), "a") as archive:
        archive.writestr("unlisted-private-data.txt", "must not upload")
    with pytest.raises(ContentError, match="unexpected"):
        publish(
            root / "detections", path, tmp_path / "publication", provider, REPO, sha
        )
    assert provider.writes == [] and provider.uploads == []
