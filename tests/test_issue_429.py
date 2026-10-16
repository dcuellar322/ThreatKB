from app import db
from app.models.jobs import Job
from app.routes.jobs import execute_job


def test_background_job_lifecycle_survives_session_reload(client):
    job = Job(kind="compile_rules", payload={}, created_user_id=1)
    db.session.add(job)
    db.session.commit()
    job_id = job.id
    result = execute_job.apply(args=[job_id]).result
    assert result["status"] == "succeeded"
    db.session.remove()
    persisted = db.session.get(Job, job_id)
    assert persisted.progress == 100
    assert persisted.started_at and persisted.finished_at
    assert persisted.result["compiled"] is True
