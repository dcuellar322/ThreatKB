"""Transactional signature editing shared by API and revision operations."""

from datetime import datetime
import json
import re
import yara
from flask import abort
from flask_login import current_user
from app import db
from app.models.yara_rule import Yara_rule, Yara_rule_history
from app.models.cfg_states import Cfg_states
from app.models.metadata import Metadata, MetadataMapping
from app.models.tags import Tags
from app.models.tags_mapping import Tags_mapping
from app.models.users import KBUser


def _scalar(value, key):
    return value.get(key) if isinstance(value, dict) else value


def save_signature(data, entity=None, *, commit=True):
    creating = entity is None
    if (
        not creating
        and not current_user.admin
        and entity.owner_user_id != current_user.id
    ):
        abort(403)
    values = {
        field: data.get(field, getattr(entity, field, None))
        for field in (
            "name",
            "description",
            "references",
            "imports",
            "strings",
            "condition",
            "category",
            "state",
        )
    }
    for field in ("mitre_tactics", "mitre_techniques", "mitre_sub_techniques"):
        value = data.get(field, getattr(entity, field, []) if entity else [])
        if not isinstance(value, list) or any(
            not isinstance(item, str) or len(item) > 64 for item in value
        ):
            abort(400, description="MITRE values must be a list of identifiers.")
        values[field] = sorted(set(value))
    values["state"] = _scalar(values["state"], "state")
    values["category"] = _scalar(values["category"], "category") or "Uncategorized"
    if (
        not values["state"]
        or not Cfg_states.query.filter_by(state=values["state"]).first()
    ):
        abort(400, description="Choose a configured signature state.")
    if not current_user.admin:
        state = Cfg_states.query.filter_by(state=values["state"]).first()
        if state.is_release_state and (creating or entity.state != state.state):
            abort(403, description="Only administrators can release signatures.")
    if not isinstance(values["name"], str) or not re.fullmatch(
        r"[A-Za-z_]\w{0,127}", values["name"], re.ASCII
    ):
        abort(400, description="Rule name must be a valid YARA identifier.")
    for field in ("strings", "condition"):
        value = values[field] or ""
        values[field] = re.sub(r"^\s*" + field + r":\s*", "", value).strip()
    if not values["condition"]:
        abort(400, description="A YARA condition is required.")
    values["imports"] = Yara_rule.get_imports_from_string(values["imports"])
    owner = _scalar(
        data.get(
            "owner_user",
            data.get(
                "owner_user_id", current_user.id if creating else entity.owner_user_id
            ),
        ),
        "id",
    )
    if owner is not None:
        owner_user = db.session.get(KBUser, owner)
        if not owner_user or not owner_user.active:
            abort(400, description="Choose an active owner.")
    values["owner_user_id"] = owner
    values["active"] = data.get("active", True if creating else entity.active)
    duplicate = Yara_rule.query.filter_by(name=values["name"]).first()
    if duplicate and (creating or duplicate.id != entity.id):
        abort(409, description="A rule with this name already exists.")
    old_tags = (
        []
        if creating
        else [
            row.text
            for row in db.session.query(Tags)
            .join(Tags_mapping, Tags_mapping.tag_id == Tags.id)
            .filter(
                Tags_mapping.source_table == "yara_rules",
                Tags_mapping.source_id == entity.id,
            )
        ]
    )
    tag_values = data.get("tags", old_tags)
    if not isinstance(tag_values, list):
        abort(400, description="Tags must be a list.")
    new_tags = sorted(set(_scalar(tag, "text") for tag in tag_values))
    if any(
        not isinstance(tag, str) or not tag.strip() or len(tag) > 256
        for tag in new_tags
    ):
        abort(400, description="Tags must contain 1–256 characters.")
    existing_mappings = (
        {}
        if creating
        else {
            field.key: mapping
            for mapping, field in db.session.query(MetadataMapping, Metadata)
            .join(Metadata)
            .filter(
                Metadata.artifact_type == 1, MetadataMapping.artifact_id == entity.id
            )
        }
    )
    old_metadata = {key: mapping.value for key, mapping in existing_mappings.items()}
    metadata_values = dict(old_metadata)
    for key, value in data.get("metadata_values", {}).items():
        value = value.get("value") if isinstance(value, dict) else value
        metadata_values[key] = str(value) if value is not None else None
    fields = {
        field.key: field
        for field in Metadata.query.filter_by(artifact_type=1, active=True)
    }
    for key, value in metadata_values.items():
        if key not in fields:
            if key in old_metadata and value == old_metadata[key]:
                # Deactivated definitions retain their historical mappings.
                continue
            abort(400, description=f"Unknown signature metadata field: {key}")
        field = fields[key]
        if field.required and not value:
            abort(400, description=f"{key} is required.")
        if (
            field.type_ == "select"
            and value
            and value not in {choice.choice for choice in field.choices}
        ):
            abort(400, description=f"Invalid choice for {key}.")
        if field.type_ == "integer" and value:
            try:
                int(value)
            except ValueError:
                abort(400, description=f"{key} must be an integer.")
    changed = (
        creating
        or any(getattr(entity, field) != value for field, value in values.items())
        or sorted(old_tags) != new_tags
        or old_metadata != metadata_values
    )
    if not changed:
        from app.routes.comments import persist_draft_comment

        persist_draft_comment(data.get("new_comment"), 1, entity.id)
        if commit:
            db.session.commit()
        return entity, False
    try:
        from app.detection import validate_signature

        validate_signature(values, entity.id if entity else None)
    except (yara.Error, ValueError) as error:
        abort(422, description=f"YARA validation failed: {error}")
    if creating:
        entity = Yara_rule(created_user_id=current_user.id, revision=1)
        db.session.add(entity)
    elif not data.get("do_not_bump_revision", False):
        entity.revision = (entity.revision or 1) + 1
    for field, value in values.items():
        setattr(entity, field, value)
    entity.modified_user_id = current_user.id
    entity.last_revision_date = datetime.now()
    db.session.flush()
    for key, value in metadata_values.items():
        mapping = existing_mappings.get(key)
        if mapping is None:
            mapping = MetadataMapping(
                metadata_id=fields[key].id,
                artifact_id=entity.id,
                created_user_id=current_user.id,
            )
            db.session.add(mapping)
        mapping.value = value
    Tags_mapping.query.filter_by(
        source_table="yara_rules", source_id=entity.id
    ).delete()
    for text in new_tags:
        tag = Tags.query.filter_by(text=text).first()
        if tag is None:
            tag = Tags(text=text)
            db.session.add(tag)
            db.session.flush()
        db.session.add(
            Tags_mapping(source_table="yara_rules", source_id=entity.id, tag_id=tag.id)
        )
    db.session.flush()
    from app.routes.comments import persist_draft_comment

    persist_draft_comment(data.get("new_comment"), 1, entity.id)
    db.session.add(
        Yara_rule_history(
            yara_rule_id=entity.id,
            revision=entity.revision,
            date_created=datetime.now(),
            state=entity.state,
            user_id=current_user.id,
            rule_json=json.dumps(entity.to_revision_dict()),
        )
    )
    if commit:
        db.session.commit()
    return entity, True
