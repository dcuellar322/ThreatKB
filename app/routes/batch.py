from flask import abort, jsonify
from flask_login import current_user

from app.routes.cfg_category_range_mapping import (
    update_cfg_category_range_mapping_current,
)
from app.models.cfg_category_range_mapping import CfgCategoryRangeMapping
from app.models.cfg_states import verify_state
from app.routes.bookmarks import batch_delete_bookmarks
from app.routes.tags_mapping import batch_create_tags_mapping, batch_delete_tags_mapping


def batch_delete(batch, artifact, session, entity_mapping, is_yara=False):
    if "ids" in batch and batch["ids"]:
        for b in batch["ids"]:
            entity = session.get(artifact, b)
            if not entity:
                abort(404)
            if not current_user.admin and entity.owner_user_id != current_user.id:
                abort(403)

        if is_yara:
            session.execute(
                artifact.__table__.update()
                .values({"active": False})
                .where(artifact.id.in_(batch["ids"]))
            )
        else:
            session.execute(
                artifact.__table__.delete().where(artifact.id.in_(batch["ids"]))
            )
        session.commit()

        if not is_yara:
            batch_delete_tags_mapping(artifact.__tablename__, batch["ids"])
        batch_delete_bookmarks(entity_mapping, batch["ids"], current_user.id)

    return jsonify(""), 200


def batch_update(batch, artifact, session, include_tags=True):
    category = dict()
    fields_to_update = dict()
    if "description" in batch and batch["description"]:
        fields_to_update["description"] = batch["description"]
    if "match_type" in batch and batch["match_type"]:
        fields_to_update["match_type"] = batch["match_type"]
    if (
        "expiration_timestamp" in batch
        and batch["expiration_timestamp"]
        and hasattr(artifact, "expiration_timestamp")
    ):
        fields_to_update["expiration_timestamp"] = batch["expiration_timestamp"]
    if "category" in batch and batch["category"] and hasattr(artifact, "category"):
        fields_to_update["category"] = (
            batch["category"]["category"]
            if batch["category"] and "category" in batch["category"]
            else None
        )
        if not CfgCategoryRangeMapping.query.filter_by(
            category=fields_to_update["category"]
        ).first():
            abort(400, description="Choose a configured category.")
    if "state" in batch and batch["state"]:
        fields_to_update["state"] = (
            verify_state(batch["state"]["state"])
            if batch["state"] and "state" in batch["state"]
            else verify_state(batch["state"])
        )
    if "owner_user" in batch and batch["owner_user"]:
        fields_to_update["owner_user_id"] = (
            batch["owner_user"]["id"]
            if batch.get("owner_user", None) and batch["owner_user"].get("id", None)
            else None
        )

    artifact_events_to_update = []
    for batch_id in batch["ids"]:
        entity = session.get(artifact, batch_id)
        if not entity:
            abort(404)
        if not current_user.admin and entity.owner_user_id != current_user.id:
            abort(403)
    if fields_to_update.get("state") and artifact.__tablename__ in ("c2ip", "c2dns"):
        from app.dynamic_whitelist import validate_dynamic_whitelist
        from app.models.whitelist import Whitelist

        kind, column = (
            ("IP", "ip") if artifact.__tablename__ == "c2ip" else ("DNS", "domain_name")
        )
        indicators = [
            getattr(row, column)
            for row in artifact.query.filter(artifact.id.in_(batch["ids"]))
        ]
        if any(
            Whitelist.hits_whitelist(value, fields_to_update["state"])
            for value in indicators
        ):
            abort(412, description="Batch includes a whitelisted indicator.")
        validate_dynamic_whitelist(indicators, kind, fields_to_update["state"])

    if fields_to_update and "ids" in batch and batch["ids"]:
        session.execute(
            artifact.__table__.update()
            .values(fields_to_update)
            .where(artifact.id.in_(batch["ids"]))
        )

        session.commit()

    if include_tags and "tags" in batch and batch["tags"]:
        batch_create_tags_mapping(artifact.__tablename__, batch["ids"], batch["tags"])

    return jsonify(""), 200
