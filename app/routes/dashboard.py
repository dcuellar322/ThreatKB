from flask import jsonify
from flask_login import login_required
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
    counts = {
        key: model.query.filter_by(active=True).count()
        for key, model in [
            ("signatures", Yara_rule),
            ("ips", C2ip),
            ("domains", C2dns),
            ("tasks", Tasks),
        ]
    }
    counts["releases"] = Release.query.count()
    counts["running_jobs"] = Job.query.filter(
        Job.status.in_(["queued", "running"])
    ).count()
    states = (
        db.session.query(Yara_rule.state, db.func.count(Yara_rule.id))
        .filter(Yara_rule.active.is_(True))
        .group_by(Yara_rule.state)
        .all()
    )
    return jsonify(
        counts=counts,
        states=[
            {"state": state or "Unassigned", "count": count} for state, count in states
        ],
        activity=[
            row.to_dict()
            for row in ActivityLog.query.order_by(ActivityLog.id.desc()).limit(8)
        ],
    )
