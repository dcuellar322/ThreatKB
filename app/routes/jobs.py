from pathlib import Path
from flask import request, jsonify, abort
from flask_login import login_required, current_user
from app import app, db
from app.celeryapp import celery
from app.models.jobs import Job, utcnow
from app.models.yara_rule import Yara_rule
from app.models.cfg_settings import Cfg_settings


def compile_rules(payload, user_id):
    from app.detection import compile_active_rules

    compile_active_rules()
    return {
        "compiled": True,
        "rule_count": Yara_rule.query.filter_by(active=True).count(),
    }


def test_rule(payload, user_id):
    from app.routes.test_yara_rule import test_yara_rule
    from app.models.files import Files

    rule = db.session.get(Yara_rule, payload["rule_id"])
    if not rule:
        raise ValueError("Signature no longer exists.")
    negative = bool(payload.get("negative", False))
    if negative:
        corpus = Cfg_settings.get_setting("NEGATIVE_TESTING_FILE_DIRECTORY")
        if not corpus or not Path(corpus).is_dir():
            raise ValueError("Configure an existing goodware corpus directory.")
        files = [str(path) for path in Path(corpus).rglob("*") if path.is_file()]
    else:
        files = [
            str(Path(item.full_path) / item.filename)
            for item in Files.query.filter_by(entity_type=1, entity_id=rule.id)
        ]
    if not files:
        raise ValueError("No samples are available for this test.")
    return test_yara_rule(rule, files, user_id, True, negative)


JOB_HANDLERS = {"compile_rules": compile_rules, "test_rule": test_rule}


@celery.task(name="threatkb.execute_job")
def execute_job(job_id):
    claimed = (
        db.session.query(Job)
        .filter_by(id=job_id, status="queued")
        .update(
            {Job.status: "running", Job.progress: 5, Job.started_at: utcnow()},
            synchronize_session=False,
        )
    )
    db.session.commit()
    if not claimed:
        return
    job = db.session.get(Job, job_id)
    try:
        handler = JOB_HANDLERS[job.kind]
        result = handler(job.payload, job.created_user_id)
        job.result, job.status, job.progress = result, "succeeded", 100
    except Exception as error:
        db.session.rollback()
        job = db.session.get(Job, job_id)
        job.status, job.error = "failed", str(error)[:4000]
        app.logger.exception("Background job failed: %s", job_id)
    job.finished_at = utcnow()
    db.session.commit()
    return job.to_dict()


def enqueue_job(kind, payload, user_id):
    job = Job(kind=kind, payload=payload, created_user_id=user_id)
    db.session.add(job)
    db.session.commit()
    try:
        execute_job.apply_async(args=[job.id], task_id=job.id, retry=False)
    except Exception:
        job.status, job.error, job.finished_at = (
            "failed",
            "Task queue is unavailable.",
            utcnow(),
        )
        db.session.commit()
        abort(
            503,
            description=f"Task queue is unavailable. Job {job.id} records this failure.",
        )
    return job


@app.route("/ThreatKB/jobs", methods=["GET", "POST"])
@login_required
def background_jobs():
    if request.method == "POST":
        data = request.get_json()
        if not isinstance(data, dict):
            abort(400, description="A JSON object is required.")
        kind, payload = data.get("kind"), data.get("payload", {})
        if kind not in JOB_HANDLERS or not isinstance(payload, dict):
            abort(400, description="Choose a supported job type and JSON payload.")
        if kind == "test_rule":
            rule = db.get_or_404(Yara_rule, payload.get("rule_id"))
            if not current_user.admin and rule.owner_user_id != current_user.id:
                abort(403)
        if kind in ("validate_content", "build_content"):
            from app.routes.content import authorize_group

            authorize_group(payload.get("group", "default"))
        job = enqueue_job(kind, payload, current_user.id)
        return jsonify(job.to_dict()), 202
    query = Job.query
    if not current_user.admin:
        query = query.filter_by(created_user_id=current_user.id)
    from app.querying import apply_sort

    q = request.args.get("q", "").strip()[:256]
    if q:
        query = query.filter(
            db.or_(
                Job.kind.like("%" + q + "%"),
                Job.status.like("%" + q + "%"),
                Job.id.like(q + "%"),
            )
        )
    limit = request.args.get("limit", 25, type=int)
    page = request.args.get("page_number", 0, type=int)
    if not 1 <= limit <= 200 or page < 0:
        abort(400, description="Choose page size 1–200 and a nonnegative page.")
    total = query.count()
    query = apply_sort(
        query,
        Job,
        request.args.get("sort_by", "created_at"),
        request.args.get("sort_dir", "DESC"),
    )
    return jsonify(
        data=[job.to_dict() for job in query.offset(page * limit).limit(limit)],
        total_count=total,
    )


@app.get("/ThreatKB/jobs/<job_id>")
@login_required
def get_background_job(job_id):
    job = db.get_or_404(Job, job_id)
    if not current_user.admin and job.created_user_id != current_user.id:
        abort(403)
    return jsonify(job.to_dict())
