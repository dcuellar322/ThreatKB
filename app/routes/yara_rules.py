from app import app, db, auto, ENTITY_MAPPING, admin_only
from app.models.yara_rule import Yara_rule_history, Yara_rule
from app.models.cfg_states import Cfg_states
from app.routes import test_yara_rule
from app.models import yara_rule, cfg_states, comments
from flask import abort, jsonify, request, Response, json
from flask_login import current_user, login_required
from app.compat import strtobool
from app.utilities import extract_yara_rules_text, extract_artifacts_text
from app.models.metadata import Metadata, MetadataMapping
from app.models.releases import (
    get_release_yara_rule_history_mapping,
    get_release_metadata,
)
from app.routes.batch import batch_update, batch_delete
from app.routes.bookmarks import is_bookmarked, delete_bookmarks
from app.routes.cfg_category_range_mapping import (
    update_cfg_category_range_mapping_current,
)
from app.routes.tags_mapping import (
    create_tags_mapping,
    delete_tags_mapping,
    get_tags_for_source,
    batch_delete_tags_mapping_for_source_id,
)
from app.routes.comments import create_comment
from app.models.cfg_settings import Cfg_settings
from app.utilities import filter_entities
import datetime
import uuid
import random
import string
import base64


@app.post("/ThreatKB/yara_rules/<int:id>/restore")
@login_required
def restore_yara_rule(id):
    entity = db.get_or_404(Yara_rule, id)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)
    from app.detection import validate_signature

    try:
        validate_signature(
            {
                key: getattr(entity, key)
                for key in ("name", "strings", "condition", "imports")
            },
            entity.id,
        )
    except Exception as error:
        abort(422, description=f"Repair this signature before restoring it: {error}")
    entity.active = True
    entity.modified_user_id = current_user.id
    db.session.commit()
    return jsonify(entity.to_dict(short=True))


@app.post("/ThreatKB/yara_rules/<int:id>/revisions/<int:revision>/restore")
@login_required
def restore_signature_revision(id, revision):
    entity = db.get_or_404(Yara_rule, id)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)
    snapshot = (
        Yara_rule_history.query.filter_by(yara_rule_id=id, revision=revision)
        .order_by(Yara_rule_history.id.desc())
        .first_or_404()
    )
    import json

    data = json.loads(snapshot.rule_json)
    data["owner_user_id"] = entity.owner_user_id
    data.pop("owner_user", None)
    data["active"] = entity.active
    data["new_comment"] = f"Restored signature content from revision {revision}."
    from app.signature_service import save_signature

    restored, changed = save_signature(data, entity)
    return jsonify(restored.to_dict(include_yara_rule_string=True))


@app.post("/ThreatKB/yara_rules/merge_signatures")
@login_required
def merge_signatures():
    from app.signature_merge import merge_sources
    from app.signature_service import save_signature

    values = request.get_json()
    sources = values.get("signatures", [])
    identities = values.get("signature_ids", [])
    if (
        not isinstance(sources, list)
        or not isinstance(identities, list)
        or len(sources) + len(identities) > 20
    ):
        abort(400)
    for identity in identities:
        rule = db.get_or_404(Yara_rule, identity)
        if not current_user.admin and rule.owner_user_id != current_user.id:
            abort(403)
        sources.append(
            rule.to_dict(include_yara_rule_string=True, short=True)["yara_rule_string"]
        )
    if any(
        not isinstance(source, str) or len(source) > 1024 * 1024 for source in sources
    ):
        abort(400)
    try:
        value = merge_sources(sources, "Merged_" + uuid.uuid4().hex[:12])
    except Exception as error:
        abort(422, description=str(error))
    if values.get("save_output"):
        staging = Cfg_states.query.filter_by(is_staging_state=1).first()
        if not staging:
            abort(409, description="Configure a staging state first.")
        value.update(state=staging.state, category="Uncategorized")
        entity, _ = save_signature(value)
        return jsonify(entity.to_dict(short=True)), 201
    return jsonify(merged_signature=Yara_rule.to_yara_rule_string(value))


@app.post("/ThreatKB/yara_rules/merge_signatures_by_id")
@login_required
def merge_signatures_by_id():
    from app.authorization import require_artifact
    from app.signature_merge import merge_sources
    from app.signature_service import save_signature

    values = request.get_json()
    source = require_artifact(1, values.get("merge_from_id"), write=True)
    destination = require_artifact(1, values.get("merge_to_id"), write=True)
    if source.id == destination.id:
        abort(400, description="Choose another signature.")
    try:
        merged = merge_sources(
            [
                source.to_dict(include_yara_rule_string=True, short=True)[
                    "yara_rule_string"
                ],
                destination.to_dict(include_yara_rule_string=True, short=True)[
                    "yara_rule_string"
                ],
            ],
            destination.name,
        )
    except Exception as error:
        abort(422, description=str(error))
    if not Cfg_states.query.filter_by(state="Merged").first():
        db.session.add(Cfg_states(state="Merged"))
        db.session.flush()
    merged["new_comment"] = (
        f"Merged signature {source.name} (EventID {source.eventid}) into this revision."
    )
    save_signature(merged, destination, commit=False)
    save_signature(
        {
            "state": "Merged",
            "new_comment": f"Merged into {destination.name} (EventID {destination.eventid}).",
        },
        source,
        commit=False,
    )
    db.session.commit()
    return jsonify(destination.to_dict(short=True))


@app.route("/ThreatKB/yara_rules", methods=["GET"])
@auto.doc()
@login_required
def get_all_yara_rules():
    """Return a list of all yara_rule artifacts.

    include_merged: variable controlling whether merged signatures are returned, default False
    include_inactive: variable controlling whether inactive signatures are returned, default False

    Pagination variables:
    page_number: page number to start on, default 0
    page_size: the size of each page, default None (dont paginate)
    sort_by: column to sort by, must exist on the Yara_rule model, default None
    sort_direction: the direction to sort by if sorting, default ASC
    searches: dictionary of column filters as {column1:filter1, column2:filter2}, columns must exist on Yara_rule model, default {}

    Return: list of yara_rule artifact dictionaries"""

    view = request.args.get("view", "Active Only")

    if view == "All":
        include_inactive = True
        include_active = True
    elif view == "Active Only":
        include_inactive = False
        include_active = True
    elif view == "Inactive Only":
        include_inactive = True
        include_active = False
    else:
        include_inactive = False
        include_active = True

    include_yara_string = bool(
        strtobool(request.args.get("include_yara_string", "False"))
    )
    short = bool(strtobool(request.args.get("short", "true")))
    include_metadata = bool(strtobool(request.args.get("include_metadata", "true")))
    include_tags = bool(strtobool(request.args.get("include_tags", "true")))
    include_comments = bool(strtobool(request.args.get("include_comments", "true")))

    if include_yara_string:
        include_yara_string = True

    include_merged = request.args.get("include_merged", False)
    searches = request.args.get("searches", "{}")
    page_number = request.args.get("page_number", False)
    page_size = request.args.get("page_size", False)
    sort_by = request.args.get("sort_by", False)
    operator = request.args.get("operator", "and")
    sort_direction = request.args.get("sort_dir", "ASC")
    exclude_totals = request.args.get("exclude_totals", False)

    response_dict = filter_entities(
        entity=yara_rule.Yara_rule,
        artifact_type=ENTITY_MAPPING["SIGNATURE"],
        searches=searches,
        page_number=page_number,
        page_size=page_size,
        sort_by=sort_by,
        sort_direction=sort_direction,
        include_metadata=include_metadata,
        exclude_totals=exclude_totals,
        default_sort="creation_date",
        include_inactive=include_inactive,
        include_tags=include_tags,
        include_comments=include_comments,
        include_active=include_active,
        include_merged=include_merged,
        include_yara_string=include_yara_string,
        short=short,
        operator=operator,
    )

    return Response(response_dict, mimetype="application/json")


@app.route("/ThreatKB/yara_rules/<int:id>", methods=["GET"])
@auto.doc()
@login_required
def get_yara_rule(id):
    """Return yara_rule artifact associated with the given id
    Return: yara_rule artifact dictionary"""
    include_yara_string = request.args.get("include_yara_string", False)
    include_revisions = strtobool(request.args.get("include_revisions", "true"))
    include_metadata = request.args.get("include_metadata", True)
    short = strtobool(request.args.get("short", "false"))

    if include_yara_string:
        include_yara_string = True

    entity = db.session.get(yara_rule.Yara_rule, id)
    if not entity:
        abort(404)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)

    return_dict = entity.to_dict(
        include_yara_rule_string=include_yara_string,
        short=short,
        include_revisions=include_revisions,
        include_metadata=include_metadata,
    )
    return_dict["bookmarked"] = (
        True
        if is_bookmarked(ENTITY_MAPPING["SIGNATURE"], id, current_user.id)
        else False
    )

    return jsonify(return_dict)


@app.route("/ThreatKB/yara_rules/<int:id>/release_mapping", methods=["GET"])
@auto.doc()
@login_required
def get_yara_rule_release_mapping(id):
    """Return yara_rule artifact associated with the given id
    Return: yara_rule artifact dictionary"""

    entity = db.session.get(yara_rule.Yara_rule, id)
    if not entity:
        abort(404)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)

    rule_history = (
        db.session.query(Yara_rule_history.id)
        .filter(Yara_rule_history.yara_rule_id == entity.id)
        .all()
    )
    if not rule_history:
        return jsonify([])

    release_mapping = get_release_yara_rule_history_mapping()
    release_metadata = get_release_metadata()
    mapping = {}
    for rh in rule_history:
        if not rh.id in mapping:
            mapping[rh.id] = []
        if rh.id in release_mapping:
            for release_id in release_mapping[rh.id]:
                mapping[rh.id].append(release_metadata[release_id])

    return_mapping = {}
    for key, val in mapping.items():
        return_mapping[int(key)] = ",".join([release["name"] for release in val])
    return jsonify(return_mapping)


@app.route(
    "/ThreatKB/yara_rules/<int:yara_rule_id>/revision/<int:revision>", methods=["GET"]
)
@auto.doc()
@login_required
def get_yara_rule_string_from_revision(yara_rule_id, revision):
    """Return yara_rule string associated with the given yara rule and revision number
    Return: yara_rule string representation"""

    current_entity = db.session.get(yara_rule.Yara_rule, yara_rule_id)
    revision_entity = (
        Yara_rule_history.query.filter_by(yara_rule_id=yara_rule_id)
        .filter_by(revision=revision)
        .order_by(Yara_rule_history.id.desc())
        .first()
    )

    if not current_entity or not revision_entity:
        abort(404)

    if not current_user.admin and current_entity.owner_user_id != current_user.id:
        abort(403)

    revision_dict = revision_entity.to_dict()
    yara_revision_dict = revision_dict["rule_json"]
    yara_rule_string = Yara_rule.to_yara_rule_string(yara_revision_dict)

    return jsonify(yara_rule_string)


@app.route("/ThreatKB/yara_rules", methods=["POST", "PUT"])
@auto.doc()
@login_required
def create_yara_rule():
    """Create yara_rule artifact
    From Data: name (str), state(str), category (str), condition (str), strings (str)
    Return: yara_rule artifact dictionary"""
    from app.signature_service import save_signature

    entity, changed = save_signature(request.get_json())
    return jsonify(entity.to_dict(include_yara_rule_string=True)), 201


@app.route("/ThreatKB/yara_rules/<int:id>", methods=["PUT"])
@auto.doc()
@login_required
def update_yara_rule(id):
    """Update yara_rule artifact
    From Data: name (str), state(str), category (str), condition (str), strings (str)
    Return: yara_rule artifact dictionary"""
    from app.signature_service import save_signature

    entity = db.get_or_404(Yara_rule, id)
    entity, changed = save_signature(request.get_json(), entity)
    return jsonify(entity.to_dict(include_yara_rule_string=True)), 200


@app.route("/ThreatKB/yara_rules/batch/edit", methods=["PUT"])
@auto.doc()
@login_required
def batch_update_yara_rules():
    """Batch update yara rules artifacts
    From Data: batch {
                 state (str),
                 owner_user (str),
                 tags (array),
                 ids (array)
               }
    Return: Success Code"""

    if "batch" in request.json and request.json["batch"]:
        return batch_update(
            batch=request.json["batch"],
            artifact=yara_rule.Yara_rule,
            session=db.session,
        )


@app.route("/ThreatKB/yara_rules/<int:id>", methods=["DELETE"])
@auto.doc()
@login_required
def delete_yara_rule(id):
    """INACTIVATE yara_rule artifact associated with id
    Return: None"""
    entity = db.get_or_404(Yara_rule, id)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)
    if entity.active:
        entity.active = False

        if not entity:
            abort(404)

        if not current_user.admin and entity.owner_user_id != current_user.id:
            abort(403)

        db.session.merge(entity)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            raise

        # delete_tags_mapping(entity.__tablename__, entity.id)
        delete_bookmarks(ENTITY_MAPPING["SIGNATURE"], id, current_user.id)
    else:
        from app.artifact_cleanup import purge_artifacts

        purge_artifacts(Yara_rule, 1, [entity.id])

    return jsonify(""), 204


@app.route("/ThreatKB/yara_rules/batch/delete", methods=["PUT"])
@auto.doc()
@login_required
def batch_delete_yara_rules():
    """Batch inactivate yara rules artifacts
    From Data: batch {
                 ids (array)
               }
    Return: Success Code"""

    if "batch" in request.json and request.json["batch"]:
        return batch_delete(
            batch=request.json["batch"],
            artifact=yara_rule.Yara_rule,
            session=db.session,
            entity_mapping=ENTITY_MAPPING["SIGNATURE"],
            is_yara=True,
        )


@app.route("/ThreatKB/yara_rules/copy", methods=["POST"])
@auto.doc()
@login_required
def copy_yara_rules():
    """Get yara strings for copy
    From Data: ids (array)
    Return: yara strings for copy"""

    signatures = []
    if (
        "copy" in request.json
        and request.json["copy"]
        and "ids" in request.json["copy"]
        and request.json["copy"]["ids"]
    ):
        for sig_id in request.json["copy"]["ids"]:
            sig = db.session.get(yara_rule.Yara_rule, sig_id)
            if not sig:
                abort(404)
            if not current_user.admin and sig.owner_user_id != current_user.id:
                abort(403)

            from app.querying import serialize_page

            value = serialize_page([sig], Yara_rule, 1, short=True)[0]
            signatures.append(Yara_rule.to_yara_rule_string(value))

    return jsonify("\n\n".join(map(str, signatures))), 200


@app.route("/ThreatKB/yara_rules/delete_all_inactive", methods=["PUT"])
@auto.doc()
@login_required
@admin_only()
def delete_all_inactive_yara_rules():
    from app.artifact_cleanup import purge_artifacts

    if not current_user.admin:
        abort(403)
    identities = db.session.scalars(
        db.select(Yara_rule.id).where(Yara_rule.active.is_(False))
    ).all()
    count = purge_artifacts(Yara_rule, 1, identities)
    return jsonify(deleted=count), 200
