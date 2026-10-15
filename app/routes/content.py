from pathlib import Path
import json
import os
import subprocess
import threading
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


def repository():
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
    files = []
    for folder in (str(root), str(root / "rules")):
        if os.path.isdir(folder):
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entry.name.endswith(".yaml") and entry.is_file():
                        info = entry.stat()
                        files.append((entry.path, info.st_mtime_ns, info.st_size))
    signature = tuple(sorted(files))
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
        return _cache["repo"]


def git(*args):
    return subprocess.run(
        ["git", "-C", str(content_root()), *args],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def commit_file(path, text, message):
    root = content_root()
    root.mkdir(parents=True, exist_ok=True)
    with lock(root / ".git" / "threatkb"):
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
            repo = Repository(root, corpus())
            if path.parent.name == "rules":
                import yara

                yara.compile(
                    source=repo.materialize(
                        [rule for rule in repo.rules if rule.get("enabled", True)]
                    )
                )
            git("add", "--", str(path.relative_to(root)))
            git(
                "-c",
                f"user.name={current_user.email}",
                "-c",
                f"user.email={current_user.id}@threatkb.local",
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
        _cache.clear()


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


JOB_HANDLERS.update(validate_content=run_content_check, build_content=run_content_build)


@app.get("/ThreatKB/content")
@login_required
def content_overview():
    repo = repository()
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
        releases.append(value)
    from collections import Counter

    history = [
        json.loads(path.read_text())
        for path in (channels() / "history").glob("*-production.json")
    ]
    monthly = Counter(
        item["promoted_at"][:7]
        for item in history
        if item["manifest"]["kind"] == "sigpack"
    )
    recent = sorted(
        builds().glob("*/manifest.json"), key=lambda p: p.stat().st_mtime, reverse=True
    )[:20]
    return jsonify(
        rule_count=len(repo.rules),
        data=[
            {k: v for k, v in r.items() if k != "strings"}
            for r in filtered[offset : offset + limit]
        ],
        total_count=len(filtered),
        groups=repo.groups,
        categories=repo.categories,
        source_digest=repo.digest(),
        builds=[json.loads(path.read_text()) for path in recent],
        channels=releases,
        metrics={
            "sigpack_releases_by_month": dict(sorted(monthly.items())),
            "baseline_releases_per_month": 4.5,
            "target_releases_per_month": 9,
            "production_history_count": len(history),
            "testing_releases": sum(r["status"] == "testing" for r in releases),
            "production_releases": sum(r["status"] == "production" for r in releases),
        },
        git_commit=git("rev-parse", "HEAD"),
        git_status=git("status", "--porcelain"),
    )


@app.route("/ThreatKB/content/rules/<identity>", methods=["GET", "PUT"])
@login_required
def content_rule(identity):
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
    if request.method == "PUT":
        data = request.get_json()
        text = data.get("yaml", "")
        value = yaml.safe_load(text)
        Draft202012Validator(RULE_SCHEMA, format_checker=FormatChecker()).validate(
            value
        )
        if value["id"] != identity:
            abort(409, description="A signature UUID is immutable.")
        for group in value.get("groups", ["default"]):
            authorize_group(group, repo)
        commit_file(path, text, f"Update signature {identity}")
    return jsonify(
        yaml=path.read_text(),
        id=identity,
        history=git(
            "log",
            "-10",
            "--format=%h %aI %s",
            "--",
            str(path.relative_to(content_root())),
        ).splitlines(),
    )


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
    _cache.clear()
    return jsonify(added=added)


@app.errorhandler(ContentError)
def content_error(error):
    return jsonify(error=str(error)), 422


@app.route("/ThreatKB/content/config/<name>", methods=["GET", "PUT"])
@login_required
@admin_only()
def content_configuration(name):
    if name not in (
        "macros",
        "categories",
        "policies",
        "pairings",
        "collections",
        "indicators",
        "components",
    ):
        abort(404)
    path = content_root() / f"{name}.yaml"
    if request.method == "PUT":
        text = request.get_json()["yaml"]
        yaml.safe_load(text)
        commit_file(path, text, f"Update content {name}")
    return jsonify(
        yaml=path.read_text()
        if path.exists()
        else (
            "[]\n"
            if name in ("pairings", "collections", "indicators", "components")
            else "{}\n"
        )
    )


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
    group = data.get("group", "default")
    authorize_group(group)
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
    Draft202012Validator(RULE_SCHEMA, format_checker=FormatChecker()).validate(rule)
    path = content_root() / "rules" / f"{identity}.yaml"
    commit_file(
        path, yaml.safe_dump(rule, sort_keys=False), f"Create signature {identity}"
    )
    return jsonify(id=identity, yaml=path.read_text(), history=[]), 201


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
