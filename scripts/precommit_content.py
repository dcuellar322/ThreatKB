"""Validate staged content and assign staged UUID placeholders without staging other edits."""

import argparse
from pathlib import Path
import re
import subprocess
import tempfile
from uuid import uuid4

from threatkb_content.engine import Repository, ContentError, UniqueLoader
import yaml


def git(root, *args, input=None):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        input=input,
        text=True,
        capture_output=True,
        check=True,
    ).stdout


def assign_id(text, identity=None):
    value = yaml.load(text, Loader=UniqueLoader)
    if not isinstance(value, dict):
        raise ContentError("A rule must be a YAML mapping")
    if value.get("id") not in (None, "AUTO"):
        return text
    identity = identity or str(uuid4())
    if "id" not in value:
        return f"id: {identity}\n" + text
    pattern = r"^(id:[ \t]*)(?:AUTO|['\"]AUTO['\"]|null|~)?([ \t]*(?:#.*)?)$"
    replaced, count = re.subn(
        pattern,
        lambda match: (
            "id: "
            + identity
            + (" " + match[2].lstrip() if match[2].strip() else match[2])
        ),
        text,
        flags=re.M,
    )
    if count != 1:
        raise ContentError("Use a top-level id: AUTO placeholder for automatic IDs")
    return replaced


def check_staged(root):
    root = Path(root).resolve()
    top = Path(git(root, "rev-parse", "--show-toplevel").strip())
    relative = root.relative_to(top)
    staged = git(
        top,
        "diff",
        "--cached",
        "--name-only",
        "-z",
        "--diff-filter=ACMDR",
        "--",
        str(relative),
    ).split("\0")
    if not any(staged):
        return []
    changes = []
    with tempfile.TemporaryDirectory(prefix="threatkb-staged-") as folder:
        snapshot = Path(folder)
        git(top, "checkout-index", "--all", "--prefix=" + str(snapshot) + "/")
        content = snapshot / relative
        for path in sorted((content / "rules").glob("*.yaml")):
            original = path.read_text()
            updated = assign_id(original)
            if updated != original:
                path.write_text(updated)
                changes.append((str(path.relative_to(snapshot)), original, updated))
        Repository(content, content / "samples").check(goodware=content / "goodware")
        # Validate every staged artifact before touching either index or worktree.
        for path, original, updated in changes:
            blob = git(top, "hash-object", "-w", "--stdin", input=updated).strip()
            mode = git(top, "ls-files", "--stage", "--", path).split()[0]
            git(top, "update-index", "--cacheinfo", f"{mode},{blob},{path}")
            working = top / path
            text = working.read_text()
            identity = yaml.load(updated, Loader=UniqueLoader)["id"]
            try:
                working_text = assign_id(text, identity)
            except ContentError, yaml.YAMLError:
                # An unstaged YAML draft may be invalid; validate only the index.
                working_text = re.sub(
                    r"^id:[ \t]*(?:AUTO|['\"]AUTO['\"]|null|~)?([ \t]*(?:#.*)?)$",
                    lambda match, identity=identity: "id: " + identity + match[1],
                    text,
                    count=1,
                    flags=re.M,
                )
            working.write_text(working_text)
    return [path for path, _, _ in changes]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("detections"))
    args = parser.parse_args()
    assigned = check_staged(args.root)
    print(f"Staged content passed; assigned {len(assigned)} UUIDs.")


if __name__ == "__main__":
    main()
