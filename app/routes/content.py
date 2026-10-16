from pathlib import Path
from contextlib import nullcontext
import json
import os
import subprocess
import stat
import threading
import hashlib
import shutil
import tempfile
import yaml
from flask import request, jsonify, abort, send_file
from flask_login import login_required, current_user
from app import app, db, admin_only
from app.models.yara_rule import Yara_rule
from app.routes.jobs import JOB_HANDLERS, enqueue_job
from threatkb_content.engine import Repository, ContentError, RULE_SCHEMA, load, lock
from jsonschema import Draft202012Validator, FormatChecker

_cache = {}
_guard = threading.Lock()
_git_cache = {}
_git_guard = threading.Lock()
CONFIG_NAMES = (
    "macros",
    "categories",
    "policies",
    "pairings",
    "collections",
    "indicators",
    "components",
)


def source_revision(head=None, inventory=None):
    """Optimistic token for both committed and external worktree changes."""
    return hashlib.sha256(
        json.dumps(
            [
                head if head is not None else git("rev-parse", "HEAD"),
                inventory if inventory is not None else file_inventory(content_root()),
            ]
        ).encode()
    ).hexdigest()


def require_revision(data):
    revision = data.get("revision")
    if not isinstance(revision, str) or len(revision) != 64:
        abort(
            428,
            description="Reload the content before saving; a source revision is required.",
        )
    if revision != source_revision():
        abort(
            409,
            description="Content changed since you opened it. Reload before saving your draft.",
        )
    return revision


def check_groups(user, groups, repo):
    for group in groups:
        policy = repo.groups.get(group)
        if policy is None:
            raise ContentError("Unknown policy group.")
        members = list(map(str, policy.get("members", [])))
        if members and not user.admin and str(user.id) not in members:
            raise ContentError("You no longer have permission to save this content.")


def save_target(payload, user):
    """Resolve only server-supported targets and recheck current access."""
    root = content_root()
    repo = Repository(root, corpus(), load_rules=False)
    if payload["action"] == "config":
        if not user.admin or payload["name"] not in CONFIG_NAMES:
            raise ContentError(
                "Administrator access is required to save repository settings."
            )
        path = root / f"{payload['name']}.yaml"
        if path.is_symlink():
            raise ContentError(
                "Linked settings must be edited in the content repository."
            )
        yaml.safe_load(payload["yaml"])
        return path
    name = payload["file_name"]
    if (
        not isinstance(name, str)
        or Path(name).name != name
        or not name.endswith(".yaml")
    ):
        raise ContentError("Invalid signature filename.")
    path = root / "rules" / name
    if not path.resolve().is_relative_to(root):
        raise ContentError("Signature path must stay inside the content repository.")
    if path.is_symlink():
        raise ContentError(
            "Linked signatures must be edited in the content repository."
        )
    if payload["action"] == "create":
        if path.exists():
            raise ContentError("This signature already exists.")
    else:
        if not path.is_file():
            raise ContentError("Signature no longer exists.")
        previous = load(path)
        if previous["id"] != payload["identity"]:
            raise ContentError("Signature identity changed. Reload before saving.")
        # Existing multi-group rules remain editable by a member of any group.
        permitted = any(
            user.admin
            or not policy.get("members")
            or str(user.id) in map(str, policy["members"])
            for group, policy in repo.groups.items()
            if group in previous.get("groups", ["default"])
        )
        if not permitted:
            raise ContentError("You no longer have permission to save this signature.")
    value = yaml.safe_load(payload["yaml"])
    Draft202012Validator(RULE_SCHEMA, format_checker=FormatChecker()).validate(value)
    if value["id"] != payload["identity"]:
        raise ContentError("A signature UUID is immutable.")
    check_groups(user, value.get("groups", ["default"]), repo)
    return path


def run_content_save(payload, user_id):
    from app.models.users import KBUser

    user = db.session.get(KBUser, user_id, populate_existing=True)
    if not user or not user.active:
        raise ContentError("The saving account is no longer active.")
    root = content_root()
    with lock(root / ".git" / "threatkb"):
        if source_revision() != payload["revision"]:
            raise ContentError(
                "Content changed while this save was pending. Reload before saving your draft."
            )
        path = save_target(payload, user)
        # Validate a private copy: readers continue seeing the last committed source.
        if git("status", "--porcelain"):
            raise ContentError(
                "Commit existing content edits before editing through the web interface."
            )
        text = payload["yaml"]
        original = path.read_text() if path.exists() else None
        if text != original:
            with tempfile.TemporaryDirectory(prefix="threatkb-save-") as folder:
                candidate = Path(folder) / "content"
                shutil.copytree(root, candidate, ignore=shutil.ignore_patterns(".git"))
                target = candidate / path.relative_to(root)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text)
                repo = Repository(candidate, corpus())
                import yara

                yara.compile(
                    source=repo.materialize(
                        [r for r in repo.rules if r.get("enabled", True)]
                    )
                )
            if source_revision() != payload["revision"]:
                raise ContentError(
                    "Content changed during validation. Reload before saving your draft."
                )
            # Recheck permissions after potentially slow validation.
            # End MySQL's repeatable-read snapshot so this sees revocations
            # committed by another request while validation was running.
            db.session.commit()
            db.session.refresh(user)
            if not user.active:
                raise ContentError("The saving account is no longer active.")
            save_target(payload, user)
            commit_file(
                path, text, payload["message"], actor=user, locked=True, validated=True
            )
        return {
            "id": payload.get("identity"),
            "file_name": path.name,
            "yaml": text,
            "revision": source_revision(),
            "git_commit": git("rev-parse", "HEAD"),
            "history": git(
                "log", "-10", "--format=%h %aI %s", "--", str(path.relative_to(root))
            ).splitlines(),
            "changed": text != original,
        }


def queue_save(payload):
    data = request.get_json()
    payload["revision"] = require_revision(data)
    if not isinstance(payload.get("yaml"), str):
        abort(400, description="Signature or configuration YAML must be text.")
    # Lightweight authorization only; full YAML/catalog/YARA validation belongs to the worker.
    return jsonify(enqueue_job("save_content", payload, current_user.id).to_dict()), 202


def file_inventory(root):
    """Detect external edits without reading every file or spawning Git processes."""
    files = []
    root = str(root)
    for folder, directories, names in os.walk(root):
        directories[:] = [name for name in directories if name != ".git"]
        for name in names:
            path = os.path.join(folder, name)
            try:
                info = os.stat(path, follow_symlinks=False)
                target = os.stat(path) if stat.S_ISLNK(info.st_mode) else None
            except FileNotFoundError:
                continue
            files.append(
                (
                    path[len(root) + 1 :],
                    info.st_mtime_ns,
                    info.st_ctime_ns,
                    info.st_size,
                    info.st_mode,
                    (target.st_mtime_ns, target.st_ctime_ns, target.st_size)
                    if target
                    else None,
                )
            )
    return tuple(sorted(files))


def git_metadata(repo, inventory):
    """Reuse read-only Git/digest results until source or Git metadata changes."""
    directory = repo.root / ".git"
    if directory.is_file():
        directory = (
            repo.root / directory.read_text().strip().removeprefix("gitdir: ")
        ).resolve()
    common = directory
    if (directory / "commondir").is_file():
        common = (directory / (directory / "commondir").read_text().strip()).resolve()
    paths = [directory / name for name in ("HEAD", "index", "commondir")]
    paths.extend(common / name for name in ("packed-refs", "config", "info/exclude"))
    paths.extend((common / "refs").rglob("*"))
    signature = []
    for path in paths:
        if path.is_file():
            info = path.stat()
            signature.append(
                (str(path), info.st_mtime_ns, info.st_ctime_ns, info.st_size)
            )
    key = (repo.root, inventory, tuple(sorted(signature)))
    with _git_guard:
        if _git_cache.get("key") != key:
            value = {
                "source_digest": repo.digest(),
                "git_commit": git("rev-parse", "HEAD"),
                "git_status": git("--no-optional-locks", "status", "--porcelain"),
            }
            _git_cache.update(key=key, value=value)
        return _git_cache["value"]


def content_root():
    return Path(
        app.config.get("CONTENT_REPOSITORY")
        or os.getenv("CONTENT_REPOSITORY")
        or Path(app.instance_path) / "dev-content"
    ).resolve()


def corpus():
    return Path(
        app.config.get("CONTENT_CORPUS") or Path(app.instance_path) / "dev-corpus"
    )


def builds():
    return Path(app.instance_path) / "content-builds"


def channels():
    return Path(app.instance_path) / "channels"


def repository(include_inventory=False):
    root = content_root()
    if not (root / ".git").exists():
        root.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "init", "-b", "main", str(root)], check=True, capture_output=True
        )
        (root / "README.md").write_text(
            "ThreatKB detection content. Add YAML rules under rules/.\n"
        )
        subprocess.run(
            ["git", "-C", str(root), "add", "README.md"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=ThreatKB",
                "-c",
                "user.email=bootstrap@threatkb.local",
                "commit",
                "-m",
                "Initialize content repository",
            ],
            check=True,
            capture_output=True,
        )
    inventory = file_inventory(root)
    signature = tuple(
        entry
        for entry in inventory
        if entry[0]
        in ("macros.yaml", "categories.yaml", "policies.yaml", "pairings.yaml")
        or (
            entry[0].endswith(".yaml")
            and entry[0].startswith("rules/")
            and entry[0].count("/") == 1
        )
    )
    with _guard:
        if (
            _cache.get("signature") != signature
            or _cache.get("root") != root
            or _cache.get("corpus") != corpus()
        ):
            _cache.update(
                signature=signature,
                root=root,
                corpus=corpus(),
                repo=Repository(root, corpus()),
            )
        repo = _cache["repo"]
        return (repo, inventory) if include_inventory else repo


def git(*args):
    return subprocess.run(
        ["git", "-C", str(content_root()), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def invalidate_repository():
    with _guard:
        _cache.clear()


def commit_file(path, text, message, actor=None, locked=False, validated=False):
    root = content_root()
    root.mkdir(parents=True, exist_ok=True)
    with nullcontext() if locked else lock(root / ".git" / "threatkb"):
        if not (root / ".git").is_dir():
            raise ContentError("Initialize the content Git repository first.")
        if git("status", "--porcelain"):
            raise ContentError(
                "Commit existing content edits before editing through the web interface."
            )
        original = path.read_text() if path.exists() else None
        if original == text:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            repo = None if validated else Repository(root, corpus())
            if not validated and path.parent.name == "rules":
                import yara

                yara.compile(
                    source=repo.materialize(
                        [rule for rule in repo.rules if rule.get("enabled", True)]
                    )
                )
            git("add", "--", str(path.relative_to(root)))
            git(
                "-c",
                f"user.name={(actor or current_user).email}",
                "-c",
                f"user.email={(actor or current_user).id}@threatkb.local",
                "commit",
                "-m",
                message,
            )
        except Exception:
            if original is None:
                path.unlink(missing_ok=True)
            else:
                path.write_text(original)
            subprocess.run(
                ["git", "-C", str(root), "reset", "--", str(path.relative_to(root))],
                capture_output=True,
            )
            raise
        invalidate_repository()


def authorize_group(group, repo=None):
    policy = (repo or repository()).groups.get(group)
    if policy is None:
        abort(400, description="Unknown policy group.")
    members = list(map(str, policy.get("members", [])))
    if members and not current_user.admin and str(current_user.id) not in members:
        abort(403)


def run_content_check(payload, user_id):
    return repository().check(
        payload.get("group", "default"), Path(app.instance_path) / "dev-goodware"
    )


def run_content_build(payload, user_id):
    kind = payload.get("kind", "sigpack")
    return Repository(content_root(), corpus(), load_rules=kind == "sigpack").build(
        builds(),
        payload.get("group", "default"),
        kind,
        Path(app.instance_path) / "dev-goodware",
    )


JOB_HANDLERS.update(
    validate_content=run_content_check,
    build_content=run_content_build,
    save_content=run_content_save,
)


@app.get("/ThreatKB/content")
@login_required
def content_overview():
    # Bootstrap before inventory so an initial GET sees the initialized Git state.
    repo, inventory = repository(include_inventory=True)
    group = request.args.get("group", "default")
    query = request.args.get("q", "").lower()
    authorize_group(group, repo)
    filtered = [
        r
        for r in repo.rules
        if group in r.get("groups", ["default"])
        and (not query or query in r["name"].lower())
    ]
    offset = max(0, request.args.get("offset", 0, type=int))
    limit = min(100, max(1, request.args.get("limit", 25, type=int)))
    releases = []
    for path in channels().glob("*/*/*.json"):
        value = json.loads(path.read_text())
        if value["manifest"]["group"] == group:
            releases.append(value)
    from collections import Counter

    history = []
    for path in (channels() / "history").glob("*-production.json"):
        value = json.loads(path.read_text())
        if value["manifest"]["group"] == group:
            history.append(value)
    monthly = Counter(
        item["promoted_at"][:7]
        for item in history
        if item["manifest"]["kind"] == "sigpack"
    )
    recent = sorted(
        builds().glob("*/manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )[:20]
    metadata = git_metadata(repo, inventory)
    return jsonify(
        rule_count=len(repo.rules),
        data=[
            {k: v for k, v in r.items() if k != "strings"}
            for r in filtered[offset : offset + limit]
        ],
        total_count=len(filtered),
        groups=repo.groups,
        categories=repo.categories,
        builds=[
            value
            for path in recent
            if (value := json.loads(path.read_text()))["group"] == group
        ],
        channels=releases,
        metrics={
            "sigpack_releases_by_month": dict(sorted(monthly.items())),
            "baseline_releases_per_month": 4.5,
            "target_releases_per_month": 9,
            "production_history_count": len(history),
            "testing_releases": sum(r["status"] == "testing" for r in releases),
            "production_releases": sum(r["status"] == "production" for r in releases),
        },
        **metadata,
        revision=source_revision(metadata["git_commit"], inventory),
    )


@app.route("/ThreatKB/content/rules/<identity>", methods=["GET", "PUT"])
@login_required
def content_rule(identity):
    if request.method == "PUT":
        data = request.get_json()
        if not isinstance(data, dict):
            abort(400, description="A JSON object is required.")
        name = data.get("file_name", "")
        if (
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or not name.endswith(".yaml")
        ):
            abort(400, description="Reload this signature before saving.")
        path = content_root() / "rules" / name
        if not path.resolve().is_relative_to(content_root()) or path.is_symlink():
            abort(400)
        if not path.is_file() or load(path).get("id") != identity:
            abort(404)
        previous = load(path)
        repo = Repository(content_root(), corpus(), load_rules=False)
        if not current_user.admin and not any(
            not policy.get("members")
            or str(current_user.id) in map(str, policy["members"])
            for group, policy in repo.groups.items()
            if group in previous.get("groups", ["default"])
        ):
            abort(403)
        return queue_save(
            {
                "action": "rule",
                "identity": identity,
                "file_name": name,
                "yaml": data.get("yaml"),
                "message": f"Update signature {identity}",
            }
        )
    repo = repository()
    rule = next((r for r in repo.rules if r["id"] == identity), None)
    if not rule:
        abort(404)
    if not current_user.admin:
        permitted = [
            name
            for name, policy in repo.groups.items()
            if not policy.get("members")
            or str(current_user.id) in map(str, policy["members"])
        ]
        if not set(rule.get("groups", ["default"])) & set(permitted):
            abort(403)
    path = content_root() / "rules" / rule["_path"]
    revision = source_revision()
    value = dict(
        yaml=path.read_text(),
        id=identity,
        file_name=path.name,
        revision=revision,
        history=git(
            "log",
            "-10",
            "--format=%h %aI %s",
            "--",
            str(path.relative_to(content_root())),
        ).splitlines(),
    )
    if source_revision() != revision:
        abort(
            409,
            description="Content changed while opening this signature. Please reopen it.",
        )
    return jsonify(value)


@app.post("/ThreatKB/content/jobs")
@login_required
def content_job():
    data = request.get_json()
    kind = data.get("kind", "validate_content")
    if kind not in ("validate_content", "build_content"):
        abort(400)
    authorize_group(data.get("payload", {}).get("group", "default"))
    return jsonify(
        enqueue_job(kind, data.get("payload", {}), current_user.id).to_dict()
    ), 202


@app.post("/ThreatKB/content/review")
@login_required
def review_content():
    author = git(
        "log",
        "-1",
        "--format=%ae",
        "--",
        "rules",
        "macros.yaml",
        "categories.yaml",
        "policies.yaml",
    ).split("@")[0]
    if author == str(current_user.id):
        abort(409, description="Another analyst must review this content.")
    review = {
        "author": author,
        "reviewer": str(current_user.id),
        "source_digest": repository().digest(),
    }
    commit_file(
        content_root() / "review.yaml",
        yaml.safe_dump(review),
        "Approve independently reviewed content",
    )
    return jsonify(review)


@app.post("/ThreatKB/content/releases/<release_id>/<action>")
@login_required
@admin_only()
def content_release_action(release_id, action):
    if "/" in release_id or ".." in release_id:
        abort(400)
    path = builds() / release_id / "manifest.json"
    if not path.is_file():
        abort(404)
    manifest = json.loads(path.read_text())
    authorize_group(manifest["group"])
    repo = repository()
    if action == "testing":
        if git("status", "--porcelain"):
            abort(409, description="Commit content changes before publishing.")
        return jsonify(repo.publish_testing(manifest, channels()))
    if action == "promote":
        current = channels() / manifest["kind"] / manifest["group"] / "testing.json"
        if (
            not current.exists()
            or json.loads(current.read_text())["manifest"]["id"] != release_id
        ):
            abort(409, description="This build is not the current testing release.")
        return jsonify(repo.promote(channels(), manifest["kind"], manifest["group"]))
    if action == "telemetry":
        data = request.get_json()
        return jsonify(
            repo.telemetry(
                channels(),
                manifest["kind"],
                manifest["group"],
                release_id,
                data["consumer"],
                data["report"],
            )
        )
    abort(404)


@app.get("/ThreatKB/content/builds/<release_id>/download")
@login_required
def download_content_build(release_id):
    from uuid import UUID

    try:
        UUID(release_id)
    except ValueError:
        abort(400)
    manifest_path = builds() / release_id / "manifest.json"
    if not manifest_path.is_file():
        abort(404)
    authorize_group(json.loads(manifest_path.read_text())["group"])
    path = builds() / f"{release_id}.zip"
    if not path.is_file():
        abort(404)
    return send_file(path, as_attachment=True, download_name=f"{release_id}.zip")


@app.post("/ThreatKB/content/export-legacy")
@login_required
@admin_only()
def export_legacy_content():
    repo = repository()
    known = {r["id"] for r in repo.rules}
    added = 0
    categories = dict(repo.categories)
    for rule in Yara_rule.query.order_by(Yara_rule.id):
        if rule.uuid in known:
            continue
        label = rule.category or "Uncategorized"
        code = next((code for code, name in categories.items() if name == label), None)
        if not code:
            import re

            code = "CAT_" + re.sub("[^A-Za-z0-9_]", "_", label).upper()
            categories[code] = label
        data = {
            "id": rule.uuid,
            "name": rule.name,
            "category": code,
            "status": (rule.state or "draft").lower()
            if (rule.state or "").lower()
            in (
                "draft",
                "imported",
                "review",
                "vetting",
                "staging",
                "released",
                "retired",
            )
            else "draft",
            "strings": rule.strings or "",
            "condition": rule.condition or "false",
            "description": rule.description or "",
            "metadata": {"legacy_eventid": rule.eventid},
            "enabled": bool(rule.active),
            "imports": __import__("re").findall(
                r'import\s+"(\w+)"', rule.imports or ""
            ),
        }
        path = content_root() / "rules" / f"{rule.uuid}.yaml"
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        added += 1
    (content_root() / "categories.yaml").write_text(yaml.safe_dump(categories))
    git("add", "rules", "categories.yaml")
    if git("diff", "--cached", "--name-only"):
        git(
            "-c",
            f"user.name={current_user.email}",
            "-c",
            f"user.email={current_user.id}@threatkb.local",
            "commit",
            "-m",
            "Export legacy signatures with stable UUIDs",
        )
    invalidate_repository()
    return jsonify(added=added)


@app.errorhandler(ContentError)
def content_error(error):
    return jsonify(error=str(error)), 422


@app.route("/ThreatKB/content/config/<name>", methods=["GET", "PUT"])
@login_required
@admin_only()
def content_configuration(name):
    if name not in CONFIG_NAMES:
        abort(404)
    path = content_root() / f"{name}.yaml"
    if request.method == "PUT":
        data = request.get_json()
        if not isinstance(data, dict):
            abort(400, description="A JSON object is required.")
        text = data.get("yaml")
        return queue_save(
            {
                "action": "config",
                "name": name,
                "yaml": text,
                "message": f"Update content {name}",
            }
        )
    if not (content_root() / ".git").exists():
        repository()  # Bootstrap only; settings reads do not need a full catalog.
    revision = source_revision()
    text = (
        path.read_text()
        if path.exists()
        else (
            "[]\n"
            if name in ("pairings", "collections", "indicators", "components")
            else "{}\n"
        )
    )
    if source_revision() != revision:
        abort(
            409,
            description="Content changed while opening settings. Please reopen them.",
        )
    return jsonify(yaml=text, revision=revision)


from app.celeryapp import celery


@celery.task(name="threatkb.promote_ready_content")
def promote_ready_content():
    result = []
    for path in channels().glob("*/*/testing.json"):
        state = json.loads(path.read_text())
        try:
            published = repository().promote(
                channels(), state["manifest"]["kind"], state["manifest"]["group"]
            )
            result.append(published["manifest"]["id"])
        except ContentError:
            pass
    return result


@app.post("/ThreatKB/content/rules")
@login_required
def create_content_rule():
    from uuid import uuid4

    data = request.get_json()
    if not isinstance(data, dict):
        abort(400, description="A JSON object is required.")
    group = data.get("group", "default")
    if not isinstance(group, str):
        abort(400, description="Choose a policy group.")
    authorize_group(group, Repository(content_root(), corpus(), load_rules=False))
    identity = str(uuid4())
    rule = {
        "id": identity,
        "name": data.get("name", ""),
        "category": data.get("category", "UC"),
        "status": "draft",
        "description": "",
        "strings": "",
        "condition": "false",
        "tags": [],
        "groups": [group],
    }
    return queue_save(
        {
            "action": "create",
            "identity": identity,
            "file_name": f"{identity}.yaml",
            "yaml": yaml.safe_dump(rule, sort_keys=False),
            "message": f"Create signature {identity}",
        }
    )


from jsonschema.exceptions import ValidationError
from yaml import YAMLError


@app.errorhandler(ValidationError)
@app.errorhandler(YAMLError)
def content_validation_error(error):
    return jsonify(error=str(error)), 422


@app.post("/ThreatKB/content/export-indicators")
@login_required
@admin_only()
def export_legacy_indicators():
    from app.models.c2ip import C2ip
    from app.models.c2dns import C2dns
    from app.models.cfg_states import Cfg_states
    from uuid import uuid5, NAMESPACE_URL

    repository()
    released = Cfg_states.query.filter_by(is_release_state=1).first()
    if not released:
        abort(409, description="Configure a release state first.")
    values = []
    for model, kind, key in ((C2ip, "ip", "ip"), (C2dns, "domain", "domain_name")):
        for entity in model.query.filter_by(active=True, state=released.state):
            values.append(
                {
                    "id": str(uuid5(NAMESPACE_URL, f"threatkb:{kind}:{entity.id}")),
                    "type": kind,
                    "value": getattr(entity, key),
                    "status": "released",
                    "groups": ["default"],
                    "source": "legacy-threatkb",
                }
            )
    commit_file(
        content_root() / "indicators.yaml",
        yaml.safe_dump(values, sort_keys=False),
        "Export reviewed legacy indicators to independent Feedpack source",
    )
    return jsonify(exported=len(values))
