from app import app, db, auto, admin_only, ENTITY_MAPPING
from app.models import metadata
from flask import abort, jsonify, request, Response
from flask_login import login_required, current_user
from dateutil import parser
import json


@app.route("/ThreatKB/metadata", methods=["GET"])
@auto.doc()
@login_required
def get_all_metadata():
    """Return all active metadata
    Return: list of metadata dictionaries"""
    active_only = request.args.get("active_only", True)
    artifact_type = request.args.get("artifact_type", 0)
    format = request.args.get("format", "list")
    filter = request.args.get("filter", None)

    if format == "dict" and filter:
        return Response(
            json.dumps([metadata.Metadata.get_metadata_dict(filter.upper())]),
            mimetype="application/json",
        )

    from sqlalchemy.orm import joinedload, selectinload

    q = metadata.Metadata.query.options(
        joinedload(metadata.Metadata.created_user),
        selectinload(metadata.Metadata.choices),
    )
    from app.compat import strtobool

    if strtobool(active_only):
        q = q.filter_by(active=True)
    if artifact_type:
        q = q.filter_by(artifact_type=int(artifact_type))

    if filter:
        return Response(
            json.dumps(
                [
                    entity.to_dict()
                    for entity in q.all()
                    if entity.to_dict()["type"] == filter
                ]
            ),
            mimetype="application/json",
        )
    else:
        return Response(
            json.dumps([entity.to_dict() for entity in q.all()]),
            mimetype="application/json",
        )


@app.route("/ThreatKB/metadata/<int:id>", methods=["GET"])
@login_required
@auto.doc()
def get_metadata(id):
    """Return task associated with given id
    Return: task dictionary"""
    entity = db.session.get(metadata.Metadata, id)
    if not entity:
        abort(404)

    return jsonify(entity.to_dict())


@app.route("/ThreatKB/metadata", methods=["POST", "PUT"])
@auto.doc()
@login_required
@admin_only()
def create_metadata():
    """Create new metadata
    From Data: key (str), active (int), artifact_type (int), type (str), default (str), show_in_table (int)
    Return: task dictionary"""

    type_ = request.json["type"]
    default = request.json.get("default", None)
    choices = request.json.get("choices", "")
    choices = [choice.strip() for choice in choices.split(",") if len(choice) > 0]

    if type_.lower() == "integer" and default:
        default = int(default)

    if type_.lower() == "date" and default:
        default = parser.parse(default)

    if type_.lower() == "select" and not choices:
        raise Exception("You must provide choices with the select option")

    entity = metadata.Metadata(
        key=request.json["key"],
        active=request.json.get("active", 1),
        artifact_type=request.json["artifact_type"],
        type_=type_,
        default=default,
        show_in_table=int(bool(request.json.get("show_in_table", 0))),
        required=request.json.get("required", 0),
        export_with_release=request.json.get("export_with_release", 1),
        created_user_id=current_user.id,
    )
    db.session.add(entity)
    db.session.commit()

    for choice in choices:
        db.session.add(
            metadata.MetadataChoices(
                choice=choice, metadata_id=entity.id, created_user_id=current_user.id
            )
        )
    db.session.commit()

    return jsonify(entity.to_dict()), 201


@app.get("/ThreatKB/metadata/columns")
@login_required
def metadata_table_columns():
    artifact_type = request.args.get("artifact_type", 1, type=int)
    fields = (
        metadata.Metadata.query.filter_by(
            artifact_type=artifact_type, active=True, show_in_table=1
        )
        .order_by(metadata.Metadata.key)
        .all()
    )
    return jsonify([field.to_dict() for field in fields])


@app.put("/ThreatKB/metadata/<int:id>")
@login_required
@admin_only()
def update_metadata_definition(id):
    """Edit a metadata definition and its enumeration without orphaning values."""
    entity = db.get_or_404(metadata.Metadata, id)
    data = request.get_json()
    type_ = data.get("type", entity.type_)
    if type_ not in {"string", "integer", "date", "multiline_comment", "select"}:
        abort(400, description="Unsupported metadata type.")
    choices = data.get("choices", [choice.choice for choice in entity.choices])
    if isinstance(choices, str):
        choices = [choice.strip() for choice in choices.split(",") if choice.strip()]
    if not isinstance(choices, list) or any(
        not isinstance(value, str) for value in choices
    ):
        abort(400, description="Choices must be a list of strings.")
    choices = list(dict.fromkeys(choices))
    values = metadata.MetadataMapping.query.filter_by(metadata_id=id).all()
    if type_ == "select":
        if not choices:
            abort(400, description="Select fields require at least one choice.")
        if any(item.value and item.value not in choices for item in values):
            abort(
                409, description="An existing artifact uses a choice you are removing."
            )
    try:
        for item in values:
            if item.value and type_ == "integer":
                int(item.value)
            if item.value and type_ == "date":
                parser.parse(item.value)
    except TypeError, ValueError:
        abort(
            409,
            description="Existing values cannot be converted to the requested type.",
        )
    entity.type_ = type_
    for field in (
        "key",
        "default",
        "active",
        "required",
        "show_in_table",
        "export_with_release",
    ):
        if field in data:
            setattr(entity, field, data[field])
    for choice in list(entity.choices):
        if choice.choice not in choices:
            db.session.delete(choice)
    existing = {choice.choice for choice in entity.choices}
    for choice in choices:
        if choice not in existing:
            db.session.add(
                metadata.MetadataChoices(
                    choice=choice, metadata_id=id, created_user_id=current_user.id
                )
            )
    db.session.commit()
    db.session.expire(entity, ["choices"])
    return jsonify(entity.to_dict())


@app.route("/ThreatKB/metadata", methods=["DELETE"])
@auto.doc()
@login_required
@admin_only()
def delete_metadata_by_id_in_param():
    """Delete metadata associated with the given id
    Return: None"""
    id = request.args.get("id")
    entity = db.session.get(metadata.Metadata, id)

    if not entity:
        abort(404)

    entity.active = False
    db.session.add(entity)
    db.session.commit()

    return jsonify(""), 204


@app.route("/ThreatKB/metadata/<int:id>", methods=["DELETE"])
@auto.doc()
@login_required
@admin_only()
def delete_metadata(id):
    """Delete metadata associated with the given id
    Return: None"""
    entity = db.session.get(metadata.Metadata, id)

    if not entity:
        abort(404)

    # db.session.delete(entity)
    entity.active = False
    db.session.add(entity)
    db.session.commit()

    return jsonify(""), 204
