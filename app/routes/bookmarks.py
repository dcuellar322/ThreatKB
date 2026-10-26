from app import app, db, admin_only, auto, ENTITY_MAPPING
from app.models.bookmarks import Bookmarks
from app.models.c2dns import C2dns
from app.models.c2ip import C2ip
from app.models.yara_rule import Yara_rule
from app.models.tasks import Tasks

from flask import abort, jsonify, request, Response
from flask_login import login_required, current_user
import json


@app.route("/ThreatKB/bookmarks", methods=["GET"])
@auto.doc()
@login_required
def get_all_bookmarks():
    """Return all bookmarks for user
    Optional Arguments: entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id (int)
    Return: list of bookmark dictionaries"""
    entity_type = request.args.get("entity_type", None)
    entity_id = request.args.get("entity_id", None)

    bookmarks = Bookmarks.query
    bookmarks = bookmarks.filter_by(user_id=current_user.id)

    if entity_type:
        bookmarks = bookmarks.filter_by(entity_type=entity_type)
    if entity_id:
        bookmarks = bookmarks.filter_by(entity_id=entity_id)

    from app.authorization import artifact_models, related_visibility
    from app.models.activity_log import ActivityLog
    from sqlalchemy.orm import joinedload

    if not current_user.admin:
        bookmarks = bookmarks.filter(
            related_visibility(Bookmarks.entity_type, Bookmarks.entity_id)
        )
    rows = bookmarks.options(joinedload(Bookmarks.user)).all()
    entities = {}
    for kind, model in artifact_models().items():
        identities = [row.entity_id for row in rows if row.entity_type == kind]
        if identities:
            entities[kind] = {
                row.id: row for row in model.query.filter(model.id.in_(identities))
            }
    keys = [(row.entity_type, row.entity_id) for row in rows]
    from sqlalchemy import tuple_

    updates = (
        dict(
            ((kind, identity), updated)
            for kind, identity, updated in db.session.query(
                ActivityLog.entity_type,
                ActivityLog.entity_id,
                db.func.max(ActivityLog.activity_date),
            )
            .filter(tuple_(ActivityLog.entity_type, ActivityLog.entity_id).in_(keys))
            .group_by(ActivityLog.entity_type, ActivityLog.entity_id)
        )
        if keys
        else {}
    )
    output = []
    for row in rows:
        entity = entities.get(row.entity_type, {}).get(row.entity_id)
        if not entity:
            continue
        name = getattr(
            entity, {1: "name", 2: "domain_name", 3: "ip", 4: "title"}[row.entity_type]
        )
        item = row.to_dict(
            name, {1: "yara_rules", 2: "c2dns", 3: "c2ips", 4: "tasks"}[row.entity_type]
        )
        updated = updates.get((row.entity_type, row.entity_id))
        item["last_updated"] = updated.isoformat() if updated else None
        if row.entity_type == 1:
            item.update(
                revision=entity.revision,
                last_revision_date=entity.last_revision_date.isoformat()
                if entity.last_revision_date
                else None,
            )
        output.append(item)
    return jsonify(output)


@app.route("/ThreatKB/bookmarks", methods=["POST", "PUT"])
@auto.doc()
@login_required
def create_bookmark():
    """Create bookmark
    From Data: entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id
    Return: bookmark dictionary"""
    from app.authorization import require_artifact

    require_artifact(request.json.get("entity_type"), request.json.get("entity_id"))
    existing = Bookmarks.query.filter_by(
        user_id=current_user.id,
        entity_type=request.json["entity_type"],
        entity_id=request.json["entity_id"],
    ).first()
    if existing:
        return jsonify(existing.to_dict()), 200
    bookmark = Bookmarks(
        entity_type=request.json["entity_type"],
        entity_id=request.json["entity_id"],
        user_id=current_user.id,
    )
    db.session.add(bookmark)
    db.session.commit()
    return jsonify(bookmark.to_dict()), 201


@app.route("/ThreatKB/bookmarks", methods=["DELETE"])
@auto.doc()
@login_required
def delete_bookmark():
    """Delete bookmark
    From Data: entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id
    Return: None"""
    bookmark = Bookmarks.query.filter_by(
        entity_type=request.args.get("entity_type", None),
        entity_id=request.args.get("entity_id", None),
        user_id=current_user.id,
    ).first()
    if not bookmark:
        abort(404)
    db.session.delete(bookmark)
    db.session.commit()
    return jsonify(""), 204


def delete_bookmarks(entity_type, entity_id, user_id):
    bookmark = Bookmarks.query.filter_by(
        entity_type=entity_type, entity_id=entity_id, user_id=user_id
    ).first()
    if bookmark:
        db.session.delete(bookmark)
        db.session.commit()


def batch_delete_bookmarks(entity_type, list_of_entity_ids, user_id):
    db.session.execute(
        Bookmarks.__table__.delete().where(
            (Bookmarks.entity_type == entity_type)
            & (Bookmarks.user_id == user_id)
            & (Bookmarks.entity_id.in_(list_of_entity_ids))
        )
    )
    db.session.commit()


def is_bookmarked(entity_type, entity_id, user_id):
    bookmark = Bookmarks.query.filter_by(
        entity_type=entity_type, entity_id=entity_id, user_id=user_id
    ).first()
    return True if bookmark else False
