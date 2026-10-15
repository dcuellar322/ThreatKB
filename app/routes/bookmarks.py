from app import app, db, admin_only, auto, ENTITY_MAPPING
from app.models.bookmarks import Bookmarks
from app.models.c2dns import C2dns
from app.models.c2ip import C2ip
from app.models.yara_rule import Yara_rule
from app.models.tasks import Tasks

from flask import abort, jsonify, request, Response
from flask_login import login_required, current_user
import json


@app.route('/ThreatKB/bookmarks', methods=['GET'])
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

    bookmarks = bookmarks.all()
    for bookmark in bookmarks:
        try:
            if bookmark.entity_type == ENTITY_MAPPING["DNS"]:
                entity = db.session.get(C2dns, bookmark.entity_id)
                bookmark.artifact_name = entity.domain_name
                bookmark.permalink_prefix = "c2dns"
            elif bookmark.entity_type == ENTITY_MAPPING["IP"]:
                entity = db.session.get(C2ip, bookmark.entity_id)
                bookmark.permalink_prefix = "c2ips"
                bookmark.artifact_name = entity.ip
            elif bookmark.entity_type == ENTITY_MAPPING["SIGNATURE"]:
                entity = db.session.get(Yara_rule, bookmark.entity_id)
                bookmark.permalink_prefix = "yara_rules"
                bookmark.artifact_name = entity.name
            elif bookmark.entity_type == ENTITY_MAPPING["TASK"]:
                entity = db.session.get(Tasks, bookmark.entity_id)
                bookmark.artifact_name = entity.title
                bookmark.permalink_prefix = "tasks"
        except Exception as e:
            app.logger.exception(e)

    from app.models.activity_log import ActivityLog
    output = []
    for bookmark in bookmarks:
        if not hasattr(bookmark, 'artifact_name') or not hasattr(bookmark, 'permalink_prefix'):
            continue
        item = bookmark.to_dict(bookmark.artifact_name, bookmark.permalink_prefix)
        updated = db.session.query(db.func.max(ActivityLog.activity_date)).filter_by(
            entity_type=bookmark.entity_type, entity_id=bookmark.entity_id).scalar()
        item['last_updated'] = updated.isoformat() if updated else None
        if bookmark.entity_type == 1:
            rule = db.session.get(Yara_rule, bookmark.entity_id)
            if rule:
                item['revision'] = rule.revision
                item['last_revision_date'] = rule.last_revision_date.isoformat() if rule.last_revision_date else None
        output.append(item)
    return jsonify(output)



@app.route('/ThreatKB/bookmarks', methods=['POST', 'PUT'])
@auto.doc()
@login_required
def create_bookmark():
    """Create bookmark
    From Data: entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id
    Return: bookmark dictionary"""
    bookmark = Bookmarks(
        entity_type=request.json['entity_type'],
        entity_id=request.json['entity_id'],
        user_id=current_user.id
    )
    db.session.add(bookmark)
    db.session.commit()
    return jsonify(bookmark.to_dict()), 201


@app.route('/ThreatKB/bookmarks', methods=['DELETE'])
@auto.doc()
@login_required
def delete_bookmark():
    """Delete bookmark
    From Data: entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id
    Return: None"""
    bookmark = Bookmarks.query.filter_by(entity_type=request.args.get("entity_type", None),
                                         entity_id=request.args.get("entity_id", None),
                                         user_id=current_user.id).first()
    if not bookmark:
        abort(404)
    db.session.delete(bookmark)
    db.session.commit()
    return jsonify(''), 204


def delete_bookmarks(entity_type, entity_id, user_id):
    bookmark = Bookmarks.query.filter_by(entity_type=entity_type,
                                         entity_id=entity_id,
                                         user_id=user_id).first()
    if bookmark:
        db.session.delete(bookmark)
        db.session.commit()


def batch_delete_bookmarks(entity_type, list_of_entity_ids, user_id):
    db.session.execute(Bookmarks.__table__
                       .delete()
                       .where((Bookmarks.entity_type == entity_type)
                              & (Bookmarks.user_id == user_id)
                              & (Bookmarks.entity_id.in_(list_of_entity_ids))))
    db.session.commit()


def is_bookmarked(entity_type, entity_id, user_id):
    bookmark = Bookmarks.query.filter_by(entity_type=entity_type,
                                         entity_id=entity_id,
                                         user_id=user_id).first()
    return True if bookmark else False
