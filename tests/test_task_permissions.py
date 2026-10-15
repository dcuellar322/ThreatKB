from app import app, db, bcrypt
from app.models.users import KBUser
from app.models.cfg_states import Cfg_states
from app.models.tasks import Tasks


def test_shared_task_is_readable_but_only_its_owner_can_update(authenticated):
    from app.models.cfg_settings import Cfg_settings

    db.session.add_all([
        Cfg_states(state="Vetting"),
        Cfg_settings(key="ENABLE_NON_ADMIN_TASK_VISIBILITY", value="true"),
        KBUser(email="task-reader@example.test", password=bcrypt.generate_password_hash("reader-password").decode(), active=True, admin=False),
    ])
    db.session.commit()
    response = authenticated.post("/ThreatKB/tasks", json={"title": "Shared task", "state": "Vetting"})
    identity = response.json["id"]
    reader = app.test_client()
    assert reader.post("/ThreatKB/login", json={"email": "task-reader@example.test", "password": "reader-password"}).status_code == 200
    task = reader.get(f"/ThreatKB/tasks/{identity}").json
    assert task["title"] == "Shared task"
    response = reader.put(f"/ThreatKB/tasks/{identity}", json={**task, "title": "Unauthorized edit"})
    assert response.status_code == 403
    db.session.expire_all()
    assert db.session.get(Tasks, identity).title == "Shared task"
