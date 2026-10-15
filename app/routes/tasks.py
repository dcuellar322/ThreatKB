from app.compat import strtobool

from app import app, db, auto, ENTITY_MAPPING
from app.models import tasks, cfg_settings, cfg_states
from flask import abort, jsonify, request, Response
from flask_login import login_required, current_user
from app.routes.batch import batch_update, batch_delete
from app.routes.bookmarks import is_bookmarked, delete_bookmarks

from app.utilities import filter_entities
from app.models.users import KBUser


def persist_task_tags(entity, values):
    from app.models.tags import Tags
    from app.models.tags_mapping import Tags_mapping

    if not isinstance(values, list):
        abort(400, description="Tags must be a list.")
    texts = [tag.get("text") if isinstance(tag, dict) else tag for tag in values]
    if any(
        not isinstance(tag, str) or not tag.strip() or len(tag) > 256
        for tag in texts
    ):
        abort(400, description="Tags require 1–256 characters.")
    texts = set(texts)
    tags = {tag.text: tag for tag in Tags.query.filter(Tags.text.in_(texts))}
    for text in texts - tags.keys():
        tag = Tags(text=text)
        db.session.add(tag)
        tags[text] = tag
    db.session.flush()
    mappings = Tags_mapping.query.filter_by(
        source_table="tasks", source_id=entity.id
    ).all()
    wanted = {tag.id for tag in tags.values()}
    existing = {mapping.tag_id for mapping in mappings}
    for mapping in mappings:
        if mapping.tag_id not in wanted:
            db.session.delete(mapping)
    for identity in wanted - existing:
        db.session.add(Tags_mapping(
            source_table="tasks", source_id=entity.id, tag_id=identity
        ))


def persist_task_metadata(entity, values):
    from app.models.metadata import Metadata, MetadataMapping
    from dateutil.parser import isoparse

    if not isinstance(values, dict):
        abort(400, description="Metadata must be an object.")
    fields = {
        field.key: field
        for field in Metadata.query.filter_by(artifact_type=4, active=True)
    }
    mappings = {
        field.key: mapping
        for mapping, field in db.session.query(MetadataMapping, Metadata)
        .join(Metadata)
        .filter(
            Metadata.artifact_type == 4,
            Metadata.active.is_(True),
            MetadataMapping.artifact_id == entity.id,
        )
    }
    if values.keys() - fields.keys():
        abort(400, description="Choose an active task metadata field.")
    for key, field in fields.items():
        mapping = mappings.get(key)
        value = values.get(key, mapping.value if mapping else field.default)
        value = value.get("value") if isinstance(value, dict) else value
        value = str(value) if value is not None else None
        if field.required and not value:
            abort(400, description=f"{key} is required.")
        if value:
            if field.type_ == "select" and value not in {
                choice.choice for choice in field.choices
            }:
                abort(400, description=f"Invalid choice for {key}.")
            try:
                if field.type_ == "integer":
                    int(value)
                elif field.type_ == "date":
                    isoparse(value)
            except (ValueError, TypeError, OverflowError):
                abort(400, description=f"Invalid {field.type_} value for {key}.")
        if mapping:
            mapping.value = value
        elif value is not None:
            db.session.add(MetadataMapping(
                metadata_id=field.id, artifact_id=entity.id,
                created_user_id=current_user.id, value=value,
            ))


def task_owner(data, default=None):
    owner = data.get("owner_user", data.get("owner_user_id", default))
    owner = owner.get("id") if isinstance(owner, dict) else owner
    if owner is not None:
        user = db.session.get(KBUser, owner)
        if not user or not user.active:
            abort(400, description="Choose an active task owner or leave unassigned.")
        owner = user.id
    return owner


@app.route("/ThreatKB/tasks", methods=["GET"])
@auto.doc()
@login_required
def get_all_tasks():
    """Return all active tasks

    Pagination variables:
    page_number: page number to start on, default 0
    page_size: the size of each page, default None (don't paginate)
    sort_by: column to sort by, must exist on the Task model, default None
    sort_direction: the direction to sort by if sorting, default ASC
    searches: dictionary of column filters as {column1:filter1, column2:filter2}, columns must exist on Task model, default {}

    Return: list of task dictionaries"""
    searches = request.args.get("searches", "{}")
    page_number = request.args.get("page_number", False)
    page_size = request.args.get("page_size", False)
    sort_by = request.args.get("sort_by", False)
    sort_direction = request.args.get("sort_dir", "ASC")
    exclude_totals = request.args.get("exclude_totals", False)
    include_metadata = bool(strtobool(request.args.get("include_metadata", "true")))
    include_tags = bool(strtobool(request.args.get("include_tags", "true")))
    include_comments = bool(strtobool(request.args.get("include_comments", "true")))

    response_dict = filter_entities(
        entity=tasks.Tasks,
        artifact_type=ENTITY_MAPPING["TASK"],
        searches=searches,
        page_number=page_number,
        page_size=page_size,
        sort_by=sort_by,
        sort_direction=sort_direction,
        include_metadata=include_metadata,
        include_tags=include_tags,
        include_comments=include_comments,
        exclude_totals=exclude_totals,
        default_sort="date_created",
        include_inactive=request.args.get("view", "Active Only") != "Active Only",
        include_active=request.args.get("view", "Active Only") != "Inactive Only",
    )

    return Response(response_dict, mimetype="application/json")


@app.route("/ThreatKB/tasks/<int:id>", methods=["GET"])
@login_required
@auto.doc()
def get_tasks(id):
    """Return task associated with given id
    Return: task dictionary"""
    from app.authorization import require_artifact

    entity = require_artifact(ENTITY_MAPPING["TASK"], id)
    return_dict = entity.to_dict()
    return_dict["bookmarked"] = (
        True if is_bookmarked(ENTITY_MAPPING["TASK"], id, current_user.id) else False
    )

    return jsonify(return_dict)


@app.route("/ThreatKB/tasks", methods=["POST", "PUT"])
@auto.doc()
@login_required
def create_tasks():
    """Create new task
    From Data: title (str), description (str), final_artifact(str), state (str)
    Return: task dictionary"""
    data = request.get_json()
    state = data.get("state")
    state = state.get("state") if isinstance(state, dict) else state
    if not state or not cfg_states.Cfg_states.query.filter_by(state=state).first():
        abort(400, description="Choose a valid task state.")
    title = data.get("title", "").strip()
    if not title or len(title) > 256:
        abort(400, description="Task title is required and limited to 256 characters.")
    entity = tasks.Tasks(
        title=title,
        description=data.get("description", ""),
        final_artifact=data.get("final_artifact", ""),
        state=state,
        created_user_id=current_user.id,
        modified_user_id=current_user.id,
        owner_user_id=task_owner(data, current_user.id),
    )
    db.session.add(entity)
    db.session.flush()
    from app.routes.comments import persist_draft_comment

    persist_draft_comment(data.get("new_comment"), ENTITY_MAPPING["TASK"], entity.id)
    persist_task_tags(entity, data.get("tags", []))
    persist_task_metadata(entity, data.get("metadata_values", {}))
    db.session.commit()

    return jsonify(entity.to_dict()), 201


@app.route("/ThreatKB/tasks/<int:id>", methods=["PUT"])
@auto.doc()
@login_required
def update_tasks(id):
    """Update task associated with given id
    From Data: title (str), description (str), final_artifact(str), state (str)
    Return: task dictionary"""
    from app.authorization import require_artifact

    entity = require_artifact(ENTITY_MAPPING["TASK"], id, write=True)
    entity.title = request.json["title"]
    entity.description = request.json["description"]
    entity.final_artifact = request.json["final_artifact"]
    entity.state = (
        request.json["state"]["state"]
        if request.json["state"] and "state" in request.json["state"]
        else request.json["state"]
    )
    entity.modified_user_id = current_user.id
    entity.owner_user_id = task_owner(request.json, entity.owner_user_id)

    from app.routes.comments import persist_draft_comment

    persist_draft_comment(
        request.json.get("new_comment"), ENTITY_MAPPING["TASK"], entity.id
    )

    if "tags" in request.json:
        persist_task_tags(entity, request.json["tags"])
    persist_task_metadata(entity, request.json.get("metadata_values", {}))
    db.session.commit()

    entity = tasks.Tasks.query.filter(tasks.Tasks.id == entity.id).first()
    return jsonify(entity.to_dict()), 200


@app.route("/ThreatKB/tasks/batch/edit", methods=["PUT"])
@auto.doc()
@login_required
def batch_update_tasks():
    """Batch update task artifacts
    From Data: batch {
                 state (str),
                 owner_user (str),
                 ids (array)
               }
    Return: Success"""

    if "batch" in request.json and request.json["batch"]:
        return batch_update(
            batch=request.json["batch"],
            artifact=tasks.Tasks,
            session=db.session,
            include_tags=True,
        )


@app.route("/ThreatKB/tasks/<int:id>", methods=["DELETE"])
@auto.doc()
@login_required
def delete_tasks(id):
    """Delete task associated with the given id
    Return: None"""
    entity = db.session.get(tasks.Tasks, id)

    if not entity:
        abort(404)

    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)
    # db.session.delete(entity)
    entity.active = False
    db.session.add(entity)
    db.session.commit()

    delete_bookmarks(ENTITY_MAPPING["TASK"], id, current_user.id)

    return jsonify(""), 204


@app.route("/ThreatKB/tasks/batch/delete", methods=["PUT"])
@auto.doc()
@login_required
def batch_delete_tasks():
    """Batch delete task artifacts
    From Data: batch {
                 ids (array)
               }
    Return: Success Code"""

    if "batch" in request.json and request.json["batch"]:
        return batch_delete(
            batch=request.json["batch"],
            artifact=tasks.Tasks,
            session=db.session,
            entity_mapping=ENTITY_MAPPING["TASK"],
        )


@app.put("/ThreatKB/tasks/delete_all_inactive")
@login_required
def purge_inactive_tasks():
    from app.artifact_cleanup import purge_artifacts

    if not current_user.admin:
        abort(403)
    identities = db.session.scalars(
        db.select(tasks.Tasks.id).where(tasks.Tasks.active.is_(False))
    ).all()
    count = purge_artifacts(tasks.Tasks, 4, identities)
    return jsonify(deleted=count), 200
