from flask import abort, jsonify
from flask_login import current_user, login_required
from app import app, db
from app.models.cfg_category_range_mapping import CfgCategoryRangeMapping
from app.models.cfg_states import Cfg_states
from app.models.users import KBUser
from app.models.tags import Tags
from app.models.tags_mapping import Tags_mapping


def selected_rows(batch, artifact, session):
    identities = batch.get("ids")
    if (
        not isinstance(identities, list)
        or not 1 <= len(identities) <= 200
        or any(type(value) != int or value < 1 for value in identities)
    ):
        abort(400, description="Select 1–200 records.")
    identities = list(dict.fromkeys(identities))
    rows = artifact.query.filter(artifact.id.in_(identities)).all()
    if len(rows) != len(identities):
        abort(404)
    if not current_user.admin and any(
        row.owner_user_id != current_user.id for row in rows
    ):
        abort(403)
    return rows


def batch_delete(batch, artifact, session, entity_mapping, is_yara=False):
    for row in selected_rows(batch, artifact, session):
        row.active = False
        row.modified_user_id = current_user.id
    session.commit()
    return jsonify(""), 200


def batch_update(batch, artifact, session, include_tags=True):
    rows = selected_rows(batch, artifact, session)
    fields = {
        key: batch[key]
        for key in ("description", "match_type", "references")
        if key in batch and hasattr(artifact, key)
    }
    if "expiration_timestamp" in batch and hasattr(artifact, "expiration_timestamp"):
        from dateutil.parser import parse

        try:
            fields["expiration_timestamp"] = (
                parse(batch["expiration_timestamp"])
                if batch["expiration_timestamp"]
                else None
            )
        except ValueError, TypeError:
            abort(400, description="Use a valid expiration date.")
    if batch.get("state"):
        state = (
            batch["state"].get("state")
            if isinstance(batch["state"], dict)
            else batch["state"]
        )
        definition = Cfg_states.query.filter_by(state=state).first()
        if not definition:
            abort(400, description="Choose a configured state.")
        if definition.is_release_state and not current_user.admin:
            abort(403)
        fields["state"] = state
    if batch.get("category") and hasattr(artifact, "category"):
        category = (
            batch["category"].get("category")
            if isinstance(batch["category"], dict)
            else batch["category"]
        )
        if not CfgCategoryRangeMapping.query.filter_by(category=category).first():
            abort(400, description="Choose a configured category.")
        fields["category"] = category
    if "owner_user" in batch:
        owner = (
            batch["owner_user"].get("id")
            if isinstance(batch["owner_user"], dict)
            else batch["owner_user"]
        )
        if owner is not None:
            user = session.get(KBUser, owner)
            if not user or not user.active:
                abort(400, description="Choose an active owner.")
        fields["owner_user_id"] = owner
    tag_values = batch.get("tags", [])
    if not isinstance(tag_values, list):
        abort(400, description="Tags must be a list.")
    texts = [tag.get("text") if isinstance(tag, dict) else tag for tag in tag_values]
    if any(
        not isinstance(text, str) or not text.strip() or len(text) > 256
        for text in texts
    ):
        abort(400, description="Tags require 1–256 characters.")
    if artifact.__tablename__ == "yara_rules":
        from app.signature_service import save_signature

        previous = {row.id: [] for row in rows}
        if texts:
            for identity, text in (
                session.query(Tags_mapping.source_id, Tags.text)
                .join(Tags, Tags.id == Tags_mapping.tag_id)
                .filter(
                    Tags_mapping.source_table == "yara_rules",
                    Tags_mapping.source_id.in_(previous),
                )
            ):
                previous[identity].append(text)
        for row in rows:
            value = dict(fields)
            if texts:
                value["tags"] = sorted(set(previous[row.id] + texts))
            save_signature(value, row, commit=False)
    else:
        # ORM writes retain validators and audit events, including release whitelists.
        for row in rows:
            for key, value in fields.items():
                setattr(row, key, value)
            if session.is_modified(row):
                row.modified_user_id = current_user.id
        if include_tags and texts:
            tags = {tag.text: tag for tag in Tags.query.filter(Tags.text.in_(texts))}
            for text in set(texts) - tags.keys():
                tag = Tags(text=text)
                session.add(tag)
                tags[text] = tag
            session.flush()
            existing = {
                (mapping.source_id, mapping.tag_id)
                for mapping in Tags_mapping.query.filter(
                    Tags_mapping.source_table == artifact.__tablename__,
                    Tags_mapping.source_id.in_([row.id for row in rows]),
                )
            }
            for row in rows:
                for tag in tags.values():
                    if (row.id, tag.id) not in existing:
                        session.add(
                            Tags_mapping(
                                source_table=artifact.__tablename__,
                                source_id=row.id,
                                tag_id=tag.id,
                            )
                        )
    session.commit()
    return jsonify(""), 200


@app.post("/ThreatKB/artifacts/<int:kind>/<int:identity>/restore")
@login_required
def restore_artifact(kind, identity):
    from app.authorization import require_artifact

    entity = require_artifact(kind, identity, write=True)
    entity.active = True
    entity.modified_user_id = current_user.id
    db.session.commit()
    return jsonify(id=entity.id, active=True)
