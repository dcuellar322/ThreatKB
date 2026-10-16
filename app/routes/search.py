from flask import request, Response, json, abort
from flask_login import login_required, current_user
from sqlalchemy import or_, and_
from app import app, db, auto, ENTITY_MAPPING
from app.models import (
    comments,
    yara_rule,
    c2dns,
    c2ip,
    tasks,
    tags,
    tags_mapping,
    metadata,
)
import json
from app.models import users
from app.models import tags_mapping
from app import cache


@cache.cached(timeout=60 * 5)
def get_caches():
    metadata_cache = metadata.Metadata.get_metadata_cache()
    tags_mapping_cache = tags_mapping.Tags_mapping.get_tags_mapping_cache()
    user_cache = users.KBUser.get_user_cache()
    comments_cache = comments.Comments.get_comment_cache()
    return metadata_cache, tags_mapping_cache, user_cache, comments_cache


@app.route("/ThreatKB/search", methods=["GET"])
@auto.doc()
@login_required
def do_search():
    tag = request.args.get("tag", None)
    state = request.args.get("state", None)
    all = request.args.get("all", None)
    artifact_type = request.args.get("artifact_type", None)
    category = request.args.get("category", None)

    # Pagination parameters with defaults
    limit = request.args.get("limit", default=100, type=int)
    offset = request.args.get("offset", default=0, type=int)

    if not 1 <= limit <= 200 or offset < 0:
        abort(400, description="Use limit 1–200 and a nonnegative offset.")

    if not tag and not state and not category and not artifact_type and not all:
        abort(400)

    if artifact_type:
        artifact_type = [a.lower() for a in artifact_type.split(",")]

    results = {"tasks": [], "ips": [], "dns": [], "signatures": []}

    # Default sorted queries
    signatures = yara_rule.Yara_rule.query.order_by(yara_rule.Yara_rule.id.desc())
    ips = c2ip.C2ip.query.order_by(c2ip.C2ip.id.desc())
    dns = c2dns.C2dns.query.order_by(c2dns.C2dns.id.desc())
    task = tasks.Tasks.query.order_by(tasks.Tasks.id.desc())

    if tag:
        signatures = (
            db.session.query(yara_rule.Yara_rule)
            .join(
                tags_mapping.Tags_mapping,
                tags_mapping.Tags_mapping.source_id == yara_rule.Yara_rule.id,
            )
            .join(tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id)
            .filter_by(text=tag)
            .filter(tags_mapping.Tags_mapping.source_table == "yara_rules")
            .order_by(yara_rule.Yara_rule.id.desc())
        )
        ips = (
            db.session.query(c2ip.C2ip)
            .join(
                tags_mapping.Tags_mapping,
                tags_mapping.Tags_mapping.source_id == c2ip.C2ip.id,
            )
            .join(tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id)
            .filter_by(text=tag)
            .filter(tags_mapping.Tags_mapping.source_table == "c2ip")
            .order_by(c2ip.C2ip.id.desc())
        )
        dns = (
            db.session.query(c2dns.C2dns)
            .join(
                tags_mapping.Tags_mapping,
                tags_mapping.Tags_mapping.source_id == c2dns.C2dns.id,
            )
            .join(tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id)
            .filter_by(text=tag)
            .filter(tags_mapping.Tags_mapping.source_table == "c2dns")
            .order_by(c2dns.C2dns.id.desc())
        )
        task = (
            db.session.query(tasks.Tasks)
            .join(
                tags_mapping.Tags_mapping,
                tags_mapping.Tags_mapping.source_id == tasks.Tasks.id,
            )
            .join(tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id)
            .filter_by(text=tag)
            .filter(tags_mapping.Tags_mapping.source_table == "tasks")
            .order_by(tasks.Tasks.id.desc())
        )

    if state:
        signatures = signatures.filter(yara_rule.Yara_rule.state == state)
        ips = ips.filter(c2ip.C2ip.state == state)
        dns = dns.filter(c2dns.C2dns.state == state)
        task = task.filter(tasks.Tasks.state == state)

    if category:
        signatures = signatures.filter(yara_rule.Yara_rule.category == category)

    if all:
        signatures = signatures.filter(
            or_(
                yara_rule.Yara_rule.name.like("%" + all + "%"),
                yara_rule.Yara_rule.category.like("%" + all + "%"),
                yara_rule.Yara_rule.state.like("%" + all + "%"),
                yara_rule.Yara_rule.strings.like("%" + all + "%"),
                yara_rule.Yara_rule.condition.like("%" + all + "%"),
                yara_rule.Yara_rule.description.like("%" + all + "%"),
                yara_rule.Yara_rule.references.like("%" + all + "%"),
                (yara_rule.Yara_rule.eventid == int(all) if all.isdigit() else False),
            )
        )

        ips = ips.filter(
            or_(
                c2ip.C2ip.state.like("%" + all + "%"),
                c2ip.C2ip.ip.like("%" + all + "%"),
                c2ip.C2ip.asn.like("%" + all + "%"),
                c2ip.C2ip.country.like("%" + all + "%"),
                c2ip.C2ip.description.like("%" + all + "%"),
                c2ip.C2ip.references.like("%" + all + "%"),
                c2ip.C2ip.state.like("%" + all + "%"),
            )
        )
        dns = dns.filter(
            or_(
                c2dns.C2dns.state.like("%" + all + "%"),
                c2dns.C2dns.domain_name.like("%" + all + "%"),
                c2dns.C2dns.description.like("%" + all + "%"),
                c2dns.C2dns.references.like("%" + all + "%"),
            )
        )
        task = task.filter(
            or_(
                tasks.Tasks.state.like("%" + all + "%"),
                tasks.Tasks.title.like("%" + all + "%"),
                tasks.Tasks.final_artifact.like("%" + all + "%"),
            )
        )

    from app.querying import visible_query, eager_people, serialize_page
    from app.models.cfg_settings import Cfg_settings

    pairs = [
        ("signatures", yara_rule.Yara_rule, 1, signatures, "signature"),
        ("ips", c2ip.C2ip, 3, ips, "ip"),
        ("dns", c2dns.C2dns, 2, dns, "dns"),
        ("tasks", tasks.Tasks, 4, task, "task"),
    ]
    totals = {}
    for key, model, kind, query, selector in pairs:
        if artifact_type and selector not in artifact_type:
            totals[key] = 0
            continue
        if not current_user.admin:
            if kind == 4:
                from app.compat import strtobool

                public = Cfg_settings.get_setting("ENABLE_NON_ADMIN_TASK_VISIBILITY")
                if not (public and strtobool(public)):
                    query = query.filter(
                        or_(
                            model.owner_user_id == current_user.id,
                            model.owner_user_id.is_(None),
                        )
                    )
            else:
                query = query.filter(model.owner_user_id == current_user.id)
        totals[key] = query.order_by(None).count()
        rows = eager_people(query, model).offset(offset).limit(limit).all()
        results[key] = serialize_page(rows, model, kind, short=True)
    sig_total, ip_total, dns_total, task_total = (
        totals[key] for key in ("signatures", "ips", "dns", "tasks")
    )

    response_data = {
        **results,
        "pagination": {
            "signatures": {"limit": limit, "offset": offset, "total": sig_total},
            "ips": {"limit": limit, "offset": offset, "total": ip_total},
            "dns": {"limit": limit, "offset": offset, "total": dns_total},
            "tasks": {"limit": limit, "offset": offset, "total": task_total},
        },
    }

    return Response(json.dumps(response_data), mimetype="application/json")
