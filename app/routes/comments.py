from app import app, db, admin_only, auto
from app.models import comments
from flask import abort, jsonify, request, Response
from flask_login import login_required, current_user
import json


@app.route("/ThreatKB/comments", methods=["GET"])
@auto.doc()
@login_required
def get_all_comments():
    """Return all comments
    Optional Arguments: entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id (int)
    Return: list of comment dictionaries"""
    app.logger.debug("args are: '%s'" % (request.args))
    entity_type = request.args.get("entity_type", None)
    entity_id = request.args.get("entity_id", None)
    entities = comments.Comments.query
    if entity_type:
        entities = entities.filter_by(entity_type=entity_type)
    if entity_id:
        entities = entities.filter_by(entity_id=entity_id)

    if not current_user.admin:
        from app.authorization import related_visibility

        entities = entities.filter(
            related_visibility(
                comments.Comments.entity_type, comments.Comments.entity_id
            )
        )
    entities = entities.order_by(comments.Comments.id).all()
    return Response(
        json.dumps([entity.to_dict() for entity in entities]),
        mimetype="application/json",
    )


@app.route("/ThreatKB/comments/<int:id>", methods=["GET"])
@auto.doc()
@login_required
def get_comments(id):
    """Return comment associated with the given id
    Return: comment dictionary"""
    entity = db.session.get(comments.Comments, id)
    if not entity:
        abort(404)
    from app.authorization import require_artifact

    require_artifact(entity.entity_type, entity.entity_id)
    return jsonify(entity.to_dict())


@app.route("/ThreatKB/comments", methods=["POST", "PUT"])
@auto.doc()
@login_required
def create_comments():
    """Create comment
    From Data: comment (str), entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id
    Return: comment dictionary"""

    return create_comment(
        request.json["comment"],
        request.json["entity_type"],
        request.json["entity_id"],
        current_user.id,
    ), 201


def create_comment(comment, entity_type, entity_id, user_id):
    from app.authorization import require_artifact

    require_artifact(entity_type, entity_id)
    if not isinstance(comment, str) or not comment.strip() or len(comment) > 100000:
        abort(400)
    entity = comments.Comments(
        comment=comment, entity_type=entity_type, entity_id=entity_id, user_id=user_id
    )
    db.session.add(entity)
    db.session.commit()
    return jsonify(entity.to_dict())


def persist_draft_comment(text, entity_type, entity_id):
    if text is None or text == "":
        return
    if not isinstance(text, str) or len(text) > 100000:
        abort(400, description="Comment must be text under 100,000 characters.")
    if text.strip():
        db.session.add(
            comments.Comments(
                comment=text.strip(),
                entity_type=entity_type,
                entity_id=entity_id,
                user_id=current_user.id,
            )
        )


@app.route("/ThreatKB/comments/<int:id>", methods=["DELETE"])
@auto.doc()
@login_required
@admin_only()
def delete_comments(id):
    """Delete comment associated with the given id
    Return: None"""
    entity = db.session.get(comments.Comments, id)
    if not entity:
        abort(404)
    db.session.delete(entity)
    db.session.commit()
    return jsonify(""), 204
