from app import db
from app.models.cfg_states import Cfg_states
from app.models.users import KBUser


def test_assign_or_leave_task_unassigned_at_creation(authenticated):
    db.session.execute(Cfg_states.__table__.insert().values(state="Vetting"))
    db.session.add(KBUser(email="owner@example.test", password="unused", active=True))
    db.session.commit()
    for owner, expected in (({"id": 2}, 2), (None, None)):
        response = authenticated.post(
            "/ThreatKB/tasks",
            json={"title": "Assigned review", "state": "Vetting", "owner_user": owner},
        )
        assert response.status_code == 201
        assert (
            response.json["owner_user"]["id"] if response.json["owner_user"] else None
        ) == expected
    assert (
        authenticated.post(
            "/ThreatKB/tasks",
            json={"title": "Bad owner", "state": "Vetting", "owner_user_id": 9999},
        ).status_code
        == 400
    )
