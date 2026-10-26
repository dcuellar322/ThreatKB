from flask import jsonify
from flask_login import login_required, current_user
from app import app, db
from app.models.yara_rule import Yara_rule
from app.models.c2ip import C2ip
from app.models.c2dns import C2dns
from app.models.tasks import Tasks
from app.models.jobs import Job
from app.models.releases import Release
from app.models.activity_log import ActivityLog


@app.get("/ThreatKB/dashboard")
@login_required
def dashboard_summary():
    from app.querying import visible_query
    from sqlalchemy.orm import joinedload

    from app.models.users import KBUser

    counts, owners = {}, {}
    kinds = {"signatures": 1, "ips": 3, "domains": 2, "tasks": 4}
    for key, model in [
        ("signatures", Yara_rule),
        ("ips", C2ip),
        ("domains", C2dns),
        ("tasks", Tasks),
    ]:
        grouped = (
            visible_query(model, kinds[key])
            .filter(model.active.is_(True))
            .with_entities(model.owner_user_id, db.func.count(model.id))
            .group_by(model.owner_user_id)
            .all()
        )
        counts[key] = sum(count for _, count in grouped)
        for identity, count in grouped:
            owners.setdefault(identity, {name: 0 for name in kinds})[key] = count
    people = (
        dict(
            db.session.query(KBUser.id, KBUser.email)
            .filter(
                KBUser.id.in_([identity for identity in owners if identity is not None])
            )
            .all()
        )
        if owners
        else {}
    )
    categories = (
        visible_query(Yara_rule, 1)
        .filter(Yara_rule.active.is_(True))
        .with_entities(Yara_rule.category, db.func.count(Yara_rule.id))
        .group_by(Yara_rule.category)
        .order_by(Yara_rule.category)
        .all()
    )
    latest = (
        (
            db.session.query(Release.id, Release.name, Release.date_created)
            .filter(Release.is_test_release == 0)
            .order_by(Release.id.desc())
            .limit(5)
            .all()
        )
        if current_user.admin
        else []
    )
    counts["releases"] = Release.query.count()
    counts["running_jobs"] = Job.query.filter(
        Job.status.in_(["queued", "running"])
    ).count()
    states = (
        visible_query(Yara_rule, 1)
        .with_entities(Yara_rule.state, db.func.count(Yara_rule.id))
        .filter(Yara_rule.active.is_(True))
        .group_by(Yara_rule.state)
        .all()
    )
    return jsonify(
        counts=counts,
        ownership=sorted(
            [
                {"email": people.get(identity, "Unassigned"), "counts": totals}
                for identity, totals in owners.items()
            ],
            key=lambda row: row["email"],
        ),
        categories=[
            {"category": category or "Uncategorized", "count": count}
            for category, count in categories
        ],
        releases=[
            {"id": identity, "name": name, "date_created": created.isoformat()}
            for identity, name, created in latest
        ],
        states=[
            {"state": state or "Unassigned", "count": count} for state, count in states
        ],
        activity=[
            row.to_dict()
            for row in ActivityLog.query.options(joinedload(ActivityLog.user))
            .order_by(ActivityLog.id.desc())
            .limit(8)
        ],
    )
