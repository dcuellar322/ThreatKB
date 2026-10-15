"""Publish a testing pack only from an independently approved, merged GitHub PR."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

import requests

from threatkb_content.engine import Repository, ContentError, atomic


class GitHub:
    def __init__(self, repository, token):
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", repository) or not token:
            raise ContentError("A GitHub repository and release token are required")
        self.base = "https://api.github.com/repos/" + repository
        self.session = requests.Session()
        self.session.headers.update(
            Authorization="Bearer " + token,
            Accept="application/vnd.github+json",
            **{"X-GitHub-Api-Version": "2022-11-28"},
        )

    def request(self, method, path, **kwargs):
        response = self.session.request(method, self.base + path, timeout=60, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else None

    def pages(self, path):
        for page in range(1, 101):
            values = self.request("GET", path, params={"per_page": 100, "page": page})
            yield from values
            if len(values) < 100:
                return
        raise ContentError("GitHub result exceeded the pagination safety limit")


def approval_for(github, repository, commit, branch="master"):
    candidates = [
        pr
        for pr in github.pages(f"/commits/{commit}/pulls")
        if pr.get("merged_at")
        and pr.get("merge_commit_sha") == commit
        and pr["base"]["ref"] == branch
        and pr["base"]["repo"]["full_name"] == repository
    ]
    if len(candidates) != 1:
        raise ContentError(
            "Release commit must be the merge of one reviewed PR into the release branch"
        )
    pr = candidates[0]
    author = pr["user"]["login"]
    reviews = {}
    for review in github.pages(f"/pulls/{pr['number']}/reviews"):
        if review.get("state") in ("APPROVED", "CHANGES_REQUESTED", "DISMISSED"):
            reviews[review["user"]["login"].lower()] = review
    approvals = [
        review
        for review in reviews.values()
        if review["state"] == "APPROVED"
        and review.get("commit_id") == pr["head"]["sha"]
        and review["user"]["login"].lower() != author.lower()
        and review["user"].get("type") == "User"
    ]
    if not approvals or any(
        review["state"] == "CHANGES_REQUESTED" for review in reviews.values()
    ):
        raise ContentError(
            "Independent human approval of the final PR head is required"
        )
    approved = sorted(approvals, key=lambda value: value["submitted_at"])[-1]
    return {
        "provider": "github",
        "author": author,
        "reviewer": approved["user"]["login"],
        "approved_at": approved["submitted_at"],
        "pull_request": pr["html_url"],
        "commit": commit,
        "head_commit": pr["head"]["sha"],
    }


def publish(
    root, manifest_path, output, github, repository, expected_commit, branch="master"
):
    root = Path(root).resolve()
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    if commit != expected_commit or dirty:
        raise ContentError("Publication requires the exact clean release commit")
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    if (
        manifest.get("git_commit") != commit
        or manifest.get("source_digest") != Repository(root, load_rules=False).digest()
    ):
        raise ContentError("Build provenance does not match the reviewed checkout")
    if manifest.get("kind") not in (
        "sigpack",
        "feedpack",
        "codepack",
    ) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", manifest.get("group", "")):
        raise ContentError("Invalid release kind/group")
    # Verify pack bytes as well as the source digest before any external write.
    import zipfile
    from hashlib import sha256

    archive = manifest_path.parent.with_suffix(".zip")
    with zipfile.ZipFile(archive) as zipped:
        if json.loads(zipped.read("manifest.json")) != manifest:
            raise ContentError("Archive manifest differs from the build manifest")
        for filename, digest in manifest["files"].items():
            if sha256(zipped.read(filename)).hexdigest() != digest:
                raise ContentError("Archive checksum mismatch: " + filename)
        expected_files = set(manifest["files"]) | {"manifest.json"}
        if set(zipped.namelist()) != expected_files or len(zipped.namelist()) != len(
            expected_files
        ):
            raise ContentError("Archive contains unexpected or duplicate files")
    proof = approval_for(github, repository, commit, branch)
    proof["source_digest"] = manifest["source_digest"]
    repo = Repository(root, load_rules=manifest["kind"] == "sigpack")
    repo.review_valid(manifest, proof)
    if not manifest.get("valid"):
        raise ContentError("Validation must pass before release")
    tag = f"testing-{manifest['kind']}-{manifest['group']}-{commit}"
    marker = f"commit: {commit}\nsource_digest: {manifest['source_digest']}"
    existing = next(
        (item for item in github.pages("/releases") if item["tag_name"] == tag), None
    )
    if existing and (
        marker not in existing.get("body", "")
        or existing.get("target_commitish") != commit
    ):
        raise ContentError("Existing release has different provenance")
    if existing and not existing["draft"]:
        if not existing.get("prerelease") or not {
            "pack.zip",
            "manifest.json",
            "testing.json",
        } <= {asset["name"] for asset in existing.get("assets", [])}:
            raise ContentError("Published testing release is incomplete or mislabeled")
        return existing
    release = existing or github.request(
        "POST",
        "/releases",
        json={
            "tag_name": tag,
            "target_commitish": commit,
            "name": f"{manifest['kind']} / {manifest['group']} / testing",
            "body": f"Testing content; production telemetry gates still apply.\n\n{marker}\n\nReviewed PR: {proof['pull_request']}",
            "draft": True,
            "prerelease": True,
        },
    )
    state = repo.publish_testing(manifest, output / "channels", review=proof)
    url = f"https://github.com/{repository}/releases/download/{tag}"
    state.update(artifact_url=url + "/pack.zip", manifest_url=url + "/manifest.json")
    state_path = output / "testing.json"
    atomic(state_path, state)
    assets = {
        "pack.zip": archive,
        "manifest.json": manifest_path,
        "testing.json": state_path,
    }
    for asset in release.get("assets", []):
        if asset["name"] in assets:
            github.request("DELETE", f"/releases/assets/{asset['id']}")
    upload = release["upload_url"].split("{")[0]
    if not upload.startswith("https://uploads.github.com/repos/" + repository + "/"):
        raise ContentError("Unexpected GitHub asset upload endpoint")
    for name, path in assets.items():
        with path.open("rb") as stream:
            response = github.session.post(
                upload,
                params={"name": name},
                data=stream,
                headers={"Content-Type": "application/octet-stream"},
                timeout=120,
            )
            response.raise_for_status()
    return github.request(
        "PATCH", f"/releases/{release['id']}", json={"draft": False, "prerelease": True}
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--branch", default="master")
    args = parser.parse_args()
    repository = os.environ["GITHUB_REPOSITORY"]
    result = publish(
        args.root,
        args.manifest,
        args.output,
        GitHub(repository, os.environ["GITHUB_TOKEN"]),
        repository,
        os.environ["GITHUB_SHA"],
        args.branch,
    )
    print(
        json.dumps(
            {"url": result["html_url"], "tag": result["tag_name"], "testing": True}
        )
    )


if __name__ == "__main__":
    main()
