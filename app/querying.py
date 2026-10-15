"""Bounded artifact queries and page-scoped related data loading."""

import json
from collections import defaultdict
from flask import abort, request
from flask_login import current_user
from sqlalchemy import and_, or_, select, exists, DateTime, String
from sqlalchemy.orm import joinedload, selectinload
from datetime import datetime
from app import db
from app.compat import strtobool
from app.models.cfg_settings import Cfg_settings
from app.models.metadata import Metadata, MetadataMapping
from app.models.tags import Tags
from app.models.tags_mapping import Tags_mapping
from app.models.comments import Comments
from app.models.users import KBUser


def visible_query(model, kind):
    query = model.query
    if current_user.admin or kind == "ACTIVITY_LOG":
        return query
    if kind == 4:
        public = Cfg_settings.get_setting("ENABLE_NON_ADMIN_TASK_VISIBILITY")
        if public and strtobool(public):
            return query
        return query.filter(
            or_(model.owner_user_id == current_user.id, model.owner_user_id.is_(None))
        )
    return query.filter(model.owner_user_id == current_user.id)


def search_predicate(model, kind, key, raw):
    operation = "contains"
    if isinstance(raw, dict):
        operation = raw.get("op", "contains")
        if operation not in (
            "contains",
            "not_contains",
            "eq",
            "neq",
            "prefix",
            "empty",
            "before_now",
            "after_now",
        ):
            abort(400, description="Unknown filter operation.")
        raw = raw.get("value", "")
    if operation in ("before_now", "after_now"):
        column = model.__table__.columns.get(key)
        date_column = column is not None and isinstance(column.type, DateTime)
        if not date_column and (
            not isinstance(kind, int)
            or not Metadata.query.filter_by(
                artifact_type=kind, key=key, active=True, type_="date"
            ).first()
        ):
            abort(400, description="Date comparisons require a date field.")
    value = str(raw)
    missing = operation == "empty" or value == "~"
    negative = operation in ("not_contains", "neq") or (
        operation == "contains" and value.startswith("!")
    )
    plain = value[1:] if operation == "contains" and value.startswith("!") else value
    needle = plain + "%" if operation == "prefix" else "%" + plain + "%"
    if operation == "before_now":
        value = "<now"
    if operation == "after_now":
        value = ">now"

    def match_column(column):
        if operation in ("eq", "neq"):
            return column == plain
        return column.like(needle)

    if key in ("owner_user.email", "user.email"):
        foreign = getattr(
            model, "owner_user_id" if key.startswith("owner") else "user_id", None
        )
        if foreign is None:
            abort(400, description="This record has no such user field.")
        if missing:
            return foreign.is_(None)
        match = exists(
            select(KBUser.id).where(KBUser.id == foreign, match_column(KBUser.email))
        )
    elif key == "tags":
        base = (
            Tags_mapping.source_table == model.__tablename__,
            Tags_mapping.source_id == model.id,
        )
        if missing:
            return ~exists(select(Tags_mapping.id).where(*base))
        match = exists(
            select(Tags_mapping.id)
            .join(Tags, Tags.id == Tags_mapping.tag_id)
            .where(*base, match_column(Tags.text))
        )
    elif key == "comments":
        base = (Comments.entity_type == kind, Comments.entity_id == model.id)
        if missing:
            return ~exists(select(Comments.id).where(*base))
        match = exists(select(Comments.id).where(*base, match_column(Comments.comment)))
    elif key in model.__table__.columns:
        column = getattr(model, key)
        if missing:
            return (
                or_(column.is_(None), column == "")
                if isinstance(column.type, String)
                else column.is_(None)
            )
        if isinstance(column.type, DateTime) and value in ("<now", ">now"):
            return (
                column < datetime.now() if value == "<now" else column > datetime.now()
            )
        match = match_column(column)
    else:
        base = (
            Metadata.artifact_type == kind,
            Metadata.key == key,
            Metadata.active.is_(True),
            MetadataMapping.artifact_id == model.id,
        )
        query = (
            select(MetadataMapping.id)
            .join(Metadata, Metadata.id == MetadataMapping.metadata_id)
            .where(*base)
        )
        if missing:
            return ~exists(
                query.where(
                    MetadataMapping.value.is_not(None), MetadataMapping.value != ""
                )
            )
        if value in ("<now", ">now"):
            match = exists(
                query.where(
                    Metadata.type_ == "date",
                    MetadataMapping.value < datetime.now().isoformat()
                    if value == "<now"
                    else MetadataMapping.value > datetime.now().isoformat(),
                )
            )
        else:
            match = exists(query.where(match_column(MetadataMapping.value)))
    return ~match if negative else match


def eager_people(query, model):
    # User caches serve artifacts. Joining tiny user tables before LIMIT made
    # MySQL hash-join every matching artifact and sort a large temporary table.
    if model.__tablename__ == "activity_log":
        return query.options(selectinload(model.user))
    return query


def serialize_page(
    rows,
    model,
    kind,
    *,
    include_metadata=True,
    include_tags=True,
    include_comments=True,
    short=True,
    include_yara_string=False,
):
    if not rows:
        return []
    if kind == "ACTIVITY_LOG":
        return [row.to_dict() for row in rows]
    ids = [row.id for row in rows]
    table = model.__tablename__
    tags = {table: {identity: [] for identity in ids}}
    comments = {table: {identity: [] for identity in ids}}
    metadata = {label: {} for label in ("SIGNATURE", "DNS", "IP")}
    user_ids = {
        getattr(row, field, None)
        for row in rows
        for field in ("created_user_id", "modified_user_id", "owner_user_id")
    }
    users = {
        user.id: user.to_dict()
        for user in KBUser.query.filter(KBUser.id.in_(user_ids - {None}))
    }
    if include_tags:
        for identity, text in (
            db.session.query(Tags_mapping.source_id, Tags.text)
            .join(Tags, Tags.id == Tags_mapping.tag_id)
            .filter(Tags_mapping.source_table == table, Tags_mapping.source_id.in_(ids))
            .order_by(Tags.text)
        ):
            tags[table][identity].append(text)
    if include_comments:
        for row in (
            Comments.query.options(joinedload(Comments.user))
            .filter(Comments.entity_type == kind, Comments.entity_id.in_(ids))
            .order_by(Comments.id)
        ):
            comments[table][row.entity_id].append(row.to_dict())
    if include_metadata and kind in (1, 2, 3):
        fields = (
            Metadata.query.options(
                joinedload(Metadata.created_user), selectinload(Metadata.choices)
            )
            .filter_by(artifact_type=kind, active=True)
            .order_by(Metadata.key)
            .all()
        )
        definitions = defaultdict(list)
        for field in fields:
            definitions[field.type_].append(field.to_dict())
        label = {1: "SIGNATURE", 2: "DNS", 3: "IP"}[kind]
        metadata[label] = {
            identity: {
                "metadata": dict(definitions),
                "metadata_values": {field.key: {} for field in fields},
            }
            for identity in ids
        }
        for mapping in MetadataMapping.query.filter(
            MetadataMapping.artifact_id.in_(ids),
            MetadataMapping.metadata_id.in_([field.id for field in fields]),
        ):
            metadata[label][mapping.artifact_id]["metadata_values"][
                mapping.metadata_object.key
            ] = mapping.to_dict()
    result = []
    for row in rows:
        if kind == 4:
            value = row.to_dict(include_comments=False, users_cache=users, include_tags=False)
            if include_comments:
                value["comments"] = comments[table][row.id]
            if include_tags:
                value["tags"] = tags[table][row.id]
        else:
            options = dict(
                include_metadata=include_metadata,
                include_tags=include_tags,
                include_comments=include_comments,
                metadata_cache=metadata,
                users_cache=users,
                tags_mapping_cache=tags,
                comments_cache=comments,
            )
            if kind == 1:
                options.update(
                    short=short, include_yara_rule_string=include_yara_string
                )
            value = row.to_dict(**options)
        result.append(value)
    return result


def filter_page(**options):
    model, kind = options["entity"], options["artifact_type"]
    try:
        filters = (
            json.loads(options["searches"])
            if isinstance(options["searches"], str)
            else options["searches"]
        )
        page = int(options["page_number"] or 0)
        size = int(options["page_size"] or 25)
    except (TypeError, ValueError):
        abort(400, description="Use valid JSON filters and integer pagination.")
    if (
        not isinstance(filters, dict)
        or len(filters) > 32
        or page < 0
        or not 1 <= size <= 200
    ):
        abort(
            400,
            description="Use at most 32 filters, a nonnegative page and page size 1–200.",
        )
    if any(
        not isinstance(key, str) or len(key) > 128 or len(str(value)) > 4096
        for key, value in filters.items()
    ):
        abort(400, description="Filter values are too long.")
    query = visible_query(model, kind)
    if hasattr(model, "active"):
        if options["include_active"] and not options["include_inactive"]:
            query = query.filter_by(active=True)
        elif options["include_inactive"] and not options["include_active"]:
            query = query.filter_by(active=False)
    if not strtobool(options["include_merged"]) and hasattr(model, "state"):
        query = query.filter(or_(model.state != "Merged", model.state.is_(None)))
    clauses = [
        search_predicate(model, kind, key, value)
        for key, value in filters.items()
        if value is not None and value != ""
    ]
    if clauses:
        query = query.filter((or_ if options["operator"] == "or" else and_)(*clauses))
    text_query = request.args.get("q", "").strip()[:256]
    name = {
        1: "name",
        2: "domain_name",
        3: "ip",
        4: "title",
        "ACTIVITY_LOG": "activity_text",
    }.get(kind)
    if text_query and name:
        query = query.filter(
            search_predicate(model, kind, name, {"op": "contains", "value": text_query})
        )
    if options["since"]:
        name = "activity_date" if kind == "ACTIVITY_LOG" else "creation_date"
        if hasattr(model, name):
            query = query.filter(getattr(model, name) > options["since"])
    sort = options["sort_by"] or options["default_sort"]
    direction = str(options["sort_direction"]).upper() if options["sort_by"] else "DESC"
    total = query.with_entities(db.func.count(model.id)).scalar()
    query = apply_sort(query, model, sort, direction, kind)
    rows = eager_people(query, model).offset(page * size).limit(size).all()
    values = serialize_page(
        rows,
        model,
        kind,
        include_metadata=options["include_metadata"],
        include_tags=options["include_tags"],
        include_comments=options["include_comments"],
        short=options["short"],
        include_yara_string=options["include_yara_string"],
    )
    payload = {
        "data": values,
        "total_count": total,
        "page_number": page,
        "page_size": size,
    }
    return json.dumps(
        values
        if options["exclude_totals"] and strtobool(options["exclude_totals"])
        else payload
    )


def apply_sort(query, model, key, direction, kind=None):
    if direction not in ("ASC", "DESC"):
        abort(400, description="Choose ASC or DESC sorting.")
    if key == "yara_rule_name" and model.__tablename__ == "yara_testing_history":
        from app.models.yara_rule import Yara_rule

        query = query.outerjoin(Yara_rule, Yara_rule.id == model.yara_rule_id)
        column = Yara_rule.name
    elif key in ("owner_user.email", "user.email"):
        from sqlalchemy.orm import aliased

        foreign = getattr(
            model, "owner_user_id" if key.startswith("owner") else "user_id", None
        )
        if foreign is None:
            abort(400, description="This record has no such user field.")
        owner = aliased(KBUser)
        query = query.outerjoin(owner, owner.id == foreign)
        column = owner.email
    elif key.startswith("metadata:"):
        field = Metadata.query.filter_by(
            artifact_type=kind, key=key[9:], active=True
        ).first()
        if not field:
            abort(400, description="Choose an active metadata field.")
        column = (
            select(MetadataMapping.value)
            .where(
                MetadataMapping.metadata_id == field.id,
                MetadataMapping.artifact_id == model.id,
            )
            .order_by(MetadataMapping.id.desc())
            .limit(1)
            .correlate(model)
            .scalar_subquery()
        )
        if field.type_ == "integer":
            column = db.cast(column, db.Integer)
    else:
        key = key.split(".")[-1]
        if key not in model.__table__.columns:
            abort(400, description="Choose a valid sort column.")
        column = getattr(model, key)
    query = query.order_by(None).order_by(
        column.asc() if direction == "ASC" else column.desc()
    )
    if key != "id":
        query = query.order_by(
            model.id.asc() if direction == "ASC" else model.id.desc()
        )
    return query
