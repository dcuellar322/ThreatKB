from app import db
from app.models.cfg_states import Cfg_states
from app.models.tasks import Tasks


def test_task_requires_valid_state_and_reports_failure(authenticated):
    for state in (None, {}, "not-configured"):
        response = authenticated.post(
            "/ThreatKB/tasks", json={"title": "Review rule", "state": state}
        )
        assert response.status_code == 400
    assert Tasks.query.count() == 0
    db.session.execute(Cfg_states.__table__.insert().values(state="Vetting"))
    db.session.commit()
    response = authenticated.post(
        "/ThreatKB/tasks", json={"title": "Review rule", "state": {"state": "Vetting"}}
    )
    assert response.status_code == 201
    assert response.json["state"] == "Vetting"
