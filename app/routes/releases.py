from flask import abort, jsonify, request, send_file, json, Response
from flask_login import login_required, current_user
from app import app, db, admin_only, auto, nocache, cache
from app.models import releases, cfg_settings
import tempfile
import uuid
import time
from app.compat import strtobool
from app.models import yara_rule, releases
import datetime
from sqlalchemy import bindparam


@app.route("/ThreatKB/releases", methods=["GET"])
@auto.doc()
@login_required
@admin_only()
def get_all_releases():
    """Return all releases in ThreatKB
    Return: list of release dictionaries"""
    from app.querying import apply_sort
    from sqlalchemy.orm import joinedload

    query = releases.Release.query.options(
        db.defer(releases.Release._release_data),
        joinedload(releases.Release.created_user),
    )
    q = request.args.get("q", "").strip()[:256]
    if q:
        query = query.filter(releases.Release.name.like("%" + q + "%"))
    total = query.count()
    query = apply_sort(
        query,
        releases.Release,
        request.args.get("sort_by", "id"),
        request.args.get("sort_dir", "DESC"),
    )
    if request.args.get("page_size"):
        size = request.args.get("page_size", 25, type=int)
        page = request.args.get("page_number", 0, type=int)
        if not 1 <= size <= 200 or page < 0:
            abort(400)
        return jsonify(
            data=[
                entity.to_small_dict()
                for entity in query.offset(page * size).limit(size)
            ],
            total_count=total,
        )
    return jsonify([entity.to_small_dict() for entity in query])


@app.route("/ThreatKB/releases/<int:release_id>", methods=["GET"])
@auto.doc()
@login_required
@admin_only()
def get_release(release_id):
    """Return release associated with release_id
    Return: release dictionary"""
    entity = db.session.get(releases.Release, release_id)

    if not entity:
        abort(404)

    return Response(json.dumps(entity.to_dict()), mimetype="application/json")


@app.route("/ThreatKB/releases/latest", methods=["GET"])
@auto.doc()
@login_required
def get_releases_latest():
    """Return the latest release data
    From Data: count (int)
    Return: list of release dictionaries"""

    count = request.args.get("count", None)
    short = strtobool(request.args.get("short", "True"))

    try:
        count = int(count)
    except:
        count = 1

    entities = (
        releases.Release.query.options(db.defer(releases.Release._release_data))
        .filter(releases.Release.is_test_release == 0)
        .order_by(releases.Release.id.desc())
        .limit(count)
    )

    if not entities:
        entities = []
    elif current_user.admin:
        entities = [
            entity.to_small_dict() if short else entity.to_dict() for entity in entities
        ]
    else:
        entities = [
            entity.to_small_dict() if short else entity.to_dict() for entity in entities
        ]

    if len(entities) == 1:
        entities = entities[0]

    return Response(json.dumps(entities), mimetype="application/json")


@app.route("/ThreatKB/releases/<int:release_id>/release_notes", methods=["GET"])
@auto.doc()
@login_required
@admin_only()
@nocache
def generate_release_notes(release_id):
    """Generate and return release notes for release associated with release_id
    Return: release text file"""
    entity = db.session.get(releases.Release, release_id)

    if not entity:
        abort(404)

    filename = str(release_id) + "_release_notes.txt"
    content = entity.generate_release_notes()
    content.seek(0)
    import io

    return send_file(
        io.BytesIO(content.read().encode("utf-8")),
        download_name=filename,
        mimetype="text/plain",
        as_attachment=True,
    )


@app.route("/ThreatKB/releases/<int:release_id>/artifact_export", methods=["GET"])
@auto.doc()
@login_required
@admin_only()
@nocache
def generate_artifact_export(release_id):
    """Generate and return artifact export zip file for the release associated with release_id
    Return: release zip file with a single file for all IPs, single file for all DNS, and consolidated category yara files"""
    entity = db.session.get(releases.Release, release_id)

    if not entity:
        abort(404)

    filename = str(release_id) + "_release.zip"
    content = entity.generate_artifact_export()
    content.seek(0)

    response = send_file(
        content, download_name=filename, mimetype="application/zip", as_attachment=True
    )
    response.call_on_close(content.close)
    return response


@app.route("/ThreatKB/releases", methods=["POST", "PUT"])
@auto.doc()
@login_required
@admin_only()
def create_release():
    """Create new release
    From Data: name (str), is_test_release (bool)
    Return: release dictionary"""
    short = strtobool(request.args.get("short", "true"))

    start_time = time.time()

    release = releases.Release(
        name=request.json.get("name", None),
        is_test_release=request.json.get("is_test_release", 0),
        created_user_id=current_user.id,
    )

    if not isinstance(release.name, str) or not release.name.strip():
        abort(400, description="A release name is required.")
    release.release_data = release.get_release_data()
    release_data = release.release_data_dict
    for attribute, label in (
        ("num_signatures", "Signatures"),
        ("num_ips", "IP"),
        ("num_dns", "DNS"),
    ):
        setattr(release, attribute, len(release_data.get(label, {}).get(label, {})))
    release.created_user = current_user
    db.session.add(release)
    db.session.flush()

    if not release.is_test_release:
        release_data = release.release_data_dict
        release_yara_rule_history_list = []
        signatures = release_data["Signatures"]["Signatures"]
        ids = [int(identity) for identity in signatures]
        history_rows = (
            yara_rule.Yara_rule_history.query.filter(
                yara_rule.Yara_rule_history.yara_rule_id.in_(ids)
            ).all()
            if ids
            else []
        )
        versions = {(row.yara_rule_id, row.revision): row for row in history_rows}
        missing = [
            identity
            for identity in ids
            if (identity, int(signatures[str(identity)]["revision"])) not in versions
        ]
        current_rules = (
            {
                rule.id: rule
                for rule in yara_rule.Yara_rule.query.filter(
                    yara_rule.Yara_rule.id.in_(missing)
                )
            }
            if missing
            else {}
        )
        for sig_id, value in signatures.items():
            revision = int(value["revision"])
            sig_id = int(sig_id)
            revision_entity = versions.get((sig_id, revision))
            if not revision_entity:
                yr = current_rules[sig_id]
                latest = yara_rule.Yara_rule_history(
                    date_created=datetime.datetime.now(),
                    revision=revision,
                    user_id=current_user.id,
                    yara_rule_id=sig_id,
                    state=yr.state,
                    rule_json=json.dumps(
                        {**value, "uuid": yr.uuid, "active": yr.active}
                    ),
                )
                db.session.add(latest)
                db.session.flush()
                revision_entity = latest

            release_yara_rule_history_list.append(
                {"yara_rules_history_id": revision_entity.id, "release_id": release.id}
            )

        if release_yara_rule_history_list:
            app.logger.debug(
                f"Inserting {len(release_yara_rule_history_list)} entries into release yara rule history table"
            )
            app.logger.debug(f"first ten are {release_yara_rule_history_list[0:9]}")
            db.session.execute(
                releases.ReleaseYaraRuleHistory.__table__.insert().values(
                    yara_rules_history_id=bindparam("yara_rules_history_id"),
                    release_id=bindparam("release_id"),
                ),
                release_yara_rule_history_list,
            )
            db.session.commit()

    db.session.commit()
    cache.delete_memoized(releases.get_release_metadata)
    cache.delete_memoized(releases.get_release_yara_rule_history_mapping)
    r = release.to_dict(short=short)
    r["build_time_seconds"] = "{0:.2f}".format(time.time() - start_time)
    return jsonify(r)


@app.route("/ThreatKB/releases/<int:release_id>", methods=["DELETE"])
@auto.doc()
@login_required
@admin_only()
def delete_release(release_id):
    """Delete release associated with release_id
    Return: None"""
    entity = db.session.get(releases.Release, release_id)
    if not entity:
        abort(404)

    db.session.query(releases.ReleaseYaraRuleHistory).filter(
        releases.ReleaseYaraRuleHistory.release_id == entity.id
    ).delete()
    db.session.delete(entity)
    db.session.commit()
    cache.delete_memoized(releases.get_release_metadata)
    cache.delete_memoized(releases.get_release_yara_rule_history_mapping)
    return jsonify(""), 204
