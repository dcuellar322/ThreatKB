import shutil
from pathlib import Path
from uuid import UUID
import yaml
import pytest
from scripts.precommit_content import assign_id, check_staged
import subprocess


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True
    ).stdout


def fixture(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    shutil.copytree(
        Path(__file__).resolve().parents[1] / "detections", root / "detections"
    )
    git(root, "init", "-b", "main")
    git(root, "add", "detections")
    return root


def test_hook_assigns_staged_uuid_and_preserves_unstaged_edits(tmp_path):
    for placeholder in ("id:", "id: # Preserve comment", "id: null # Context"):
        assigned = assign_id(placeholder, "6feb2c96-6783-42c0-961a-17764cd996f0")
        assert yaml.safe_load(assigned)["id"] == "6feb2c96-6783-42c0-961a-17764cd996f0"
        if "#" in placeholder:
            assert placeholder.split("#")[1] in assigned
    root = fixture(tmp_path)
    path = root / "detections/rules/demo.yaml"
    value = yaml.safe_load(path.read_text())
    value["id"] = "AUTO"
    path.write_text(yaml.safe_dump(value))
    git(root, "add", "detections/rules/demo.yaml")
    path.write_text(path.read_text() + "\n# Unstaged analyst context\n")
    assert check_staged(root / "detections") == ["detections/rules/demo.yaml"]
    staged = git(root, "show", ":detections/rules/demo.yaml")
    identity = yaml.safe_load(staged)["id"]
    assert str(UUID(identity)) == identity
    assert "# Unstaged analyst context" not in staged
    assert "# Unstaged analyst context" in path.read_text()
    assert yaml.safe_load(path.read_text())["id"] == identity


def test_hook_validates_staged_snapshot_and_leaves_invalid_index_unchanged(tmp_path):
    root = fixture(tmp_path)
    path = root / "detections/rules/demo.yaml"
    value = yaml.safe_load(path.read_text())
    value["id"] = "AUTO"
    value["condition"] = "this is invalid"
    path.write_text(yaml.safe_dump(value))
    git(root, "add", "detections/rules/demo.yaml")
    before = git(root, "show", ":detections/rules/demo.yaml")
    value["condition"] = "true"
    path.write_text(yaml.safe_dump(value))
    with pytest.raises(Exception):
        check_staged(root / "detections")
    assert git(root, "show", ":detections/rules/demo.yaml") == before


def test_hook_does_not_validate_or_stage_invalid_unstaged_draft(tmp_path):
    root = fixture(tmp_path)
    path = root / "detections/rules/demo.yaml"
    value = yaml.safe_load(path.read_text())
    value["id"] = "AUTO"
    path.write_text(yaml.safe_dump(value))
    git(root, "add", "detections/rules/demo.yaml")
    path.write_text(path.read_text() + "\ninvalid_draft: [\n")
    check_staged(root / "detections")
    staged = git(root, "show", ":detections/rules/demo.yaml")
    assert "invalid_draft" not in staged
    assert "invalid_draft: [" in path.read_text()
    assert yaml.safe_load(staged)["id"] in path.read_text()
