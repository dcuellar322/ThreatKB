from flask import request, Response, json, abort
from flask_login import login_required, current_user
from sqlalchemy import or_, and_
from app import app, db, auto, ENTITY_MAPPING
from app.models import comments, yara_rule, c2dns, c2ip, tasks, tags, tags_mapping, metadata
import json
from app.models import users
from app.models import tags_mapping
from app import cache


@cache.cached(timeout=60*5)
def get_caches():
    metadata_cache = metadata.Metadata.get_metadata_cache()
    tags_mapping_cache = tags_mapping.Tags_mapping.get_tags_mapping_cache()
    user_cache = users.KBUser.get_user_cache()
    comments_cache = comments.Comments.get_comment_cache()
    return metadata_cache, tags_mapping_cache, user_cache, comments_cache


@app.route('/ThreatKB/search', methods=['GET'])
@auto.doc()
@login_required
def do_search():
    tag = request.args.get("tag", None)
    state = request.args.get('state', None)
    all = request.args.get("all", None)
    artifact_type = request.args.get('artifact_type', None)
    category = request.args.get('category', None)

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
        signatures = db.session.query(yara_rule.Yara_rule).join(tags_mapping.Tags_mapping,
                                                                tags_mapping.Tags_mapping.source_id == yara_rule.Yara_rule.id).join(
            tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id).filter_by(text=tag).filter(
            tags_mapping.Tags_mapping.source_table == "yara_rules").order_by(yara_rule.Yara_rule.id.desc())
        ips = db.session.query(c2ip.C2ip).join(tags_mapping.Tags_mapping,
                                               tags_mapping.Tags_mapping.source_id == c2ip.C2ip.id).join(
            tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id).filter_by(text=tag).filter(
            tags_mapping.Tags_mapping.source_table == "c2ip").order_by(c2ip.C2ip.id.desc())
        dns = db.session.query(c2dns.C2dns).join(tags_mapping.Tags_mapping,
                                                 tags_mapping.Tags_mapping.source_id == c2dns.C2dns.id).join(
            tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id).filter_by(text=tag).filter(
            tags_mapping.Tags_mapping.source_table == "c2dns").order_by(c2dns.C2dns.id.desc())
        task = db.session.query(tasks.Tasks).join(tags_mapping.Tags_mapping,
                                                  tags_mapping.Tags_mapping.source_id == tasks.Tasks.id).join(
            tags.Tags, tags.Tags.id == tags_mapping.Tags_mapping.tag_id).filter_by(text=tag).filter(
            tags_mapping.Tags_mapping.source_table == "tasks").order_by(tasks.Tasks.id.desc())

    if state:
        signatures = signatures.filter(yara_rule.Yara_rule.state == state)
        ips = ips.filter(c2ip.C2ip.state == state)
        dns = dns.filter(c2dns.C2dns.state == state)
        task = task.filter(tasks.Tasks.state == state)

    if category:
        signatures = signatures.filter(yara_rule.Yara_rule.category == category)

    if all:
        signatures = signatures.filter(
            or_(yara_rule.Yara_rule.name.like("%" + all + "%"), yara_rule.Yara_rule.category.like("%" + all + "%"),
                yara_rule.Yara_rule.state.like("%" + all + "%"), yara_rule.Yara_rule.strings.like("%" + all + "%"),
                yara_rule.Yara_rule.condition.like("%" + all + "%"),
                yara_rule.Yara_rule.description.like("%" + all + "%"),
                yara_rule.Yara_rule.references.like("%" + all + "%"),
                (yara_rule.Yara_rule.eventid == int(all) if all.isdigit() else False)))

        ips = ips.filter(or_(c2ip.C2ip.state.like("%" + all + "%"),
                             c2ip.C2ip.ip.like("%" + all + "%"),
                             c2ip.C2ip.asn.like("%" + all + "%"),
                             c2ip.C2ip.country.like("%" + all + "%"),
                             c2ip.C2ip.description.like("%" + all + "%"),
                             c2ip.C2ip.references.like("%" + all + "%"),
                             c2ip.C2ip.state.like("%" + all + "%"), ))
        dns = dns.filter(or_(c2dns.C2dns.state.like("%" + all + "%"),
                             c2dns.C2dns.domain_name.like("%" + all + "%"),
                             c2dns.C2dns.description.like("%" + all + "%"),
                             c2dns.C2dns.references.like("%" + all + "%"),
                             ))
        task = task.filter(or_(tasks.Tasks.state.like("%" + all + "%"), tasks.Tasks.title.like("%" + all + "%"),
                               tasks.Tasks.final_artifact.like("%" + all + "%")))

    metadata_cache, tags_mapping_cache, user_cache, comments_cache = get_caches()

    # Per-artifact-type total counts
    sig_total = signatures.order_by(None).count() if not artifact_type or "signature" in artifact_type else 0
    ip_total = ips.order_by(None).count() if not artifact_type or "ip" in artifact_type else 0
    dns_total = dns.order_by(None).count() if not artifact_type or "dns" in artifact_type else 0
    task_total = task.order_by(None).count() if not artifact_type or "task" in artifact_type else 0

    if not artifact_type or "signature" in artifact_type:
        results["signatures"] = [
            signature.to_dict(comments_cache=comments_cache, metadata_cache=metadata_cache, users_cache=user_cache, tags_mapping_cache=tags_mapping_cache)
            for signature in signatures.offset(offset).limit(limit).all()
        ]

    if not artifact_type or "ip" in artifact_type:
        results["ips"] = [
            ip.to_dict(comments_cache=comments_cache, metadata_cache=metadata_cache, users_cache=user_cache, tags_mapping_cache=tags_mapping_cache)
            for ip in ips.offset(offset).limit(limit).all()
        ]

    if not artifact_type or "dns" in artifact_type:
        results["dns"] = [
            d.to_dict(comments_cache=comments_cache, metadata_cache=metadata_cache, users_cache=user_cache, tags_mapping_cache=tags_mapping_cache)
            for d in dns.offset(offset).limit(limit).all()
        ]

    if not artifact_type or "task" in artifact_type:
        results["tasks"] = [
            t.to_dict() for t in task.offset(offset).limit(limit).all()
        ]

    response_data = {
        **results,
        "pagination": {
            "signatures": {
                "limit": limit,
                "offset": offset,
                "total": sig_total
            },
            "ips": {
                "limit": limit,
                "offset": offset,
                "total": ip_total
            },
            "dns": {
                "limit": limit,
                "offset": offset,
                "total": dns_total
            },
            "tasks": {
                "limit": limit,
                "offset": offset,
                "total": task_total
            }
        }
    }

    return Response(json.dumps(response_data), mimetype='application/json')
