from app import db
from app.models.tasks import Tasks
from app.models.activity_log import ActivityLog


def test_artifact_and_audit_share_transaction(authenticated):
    with authenticated.application.test_request_context():
        task = Tasks(title="transaction check", created_user_id=1, modified_user_id=1)
        db.session.add(task)
        db.session.flush()
        assert ActivityLog.query.count() == 1
        db.session.rollback()
        assert Tasks.query.count() == 0
        assert ActivityLog.query.count() == 0
