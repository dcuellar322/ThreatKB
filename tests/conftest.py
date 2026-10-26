import os

os.environ["THREATKB_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["THREATKB_SECRET_KEY"] = "isolated-test-secret"

import pytest
from flask import request_started, g
from app import app, db, cache, bcrypt
from app.models.users import KBUser


@pytest.fixture
def client(tmp_path):
    previous_instance = app.instance_path
    app.instance_path = str(tmp_path / "instance")
    from pathlib import Path

    Path(app.instance_path).mkdir()
    app.config.update(TESTING=True)
    with app.app_context():
        db.create_all()
        cache.clear()
        user = KBUser(
            email="analyst@example.test",
            password=bcrypt.generate_password_hash("test-password").decode(),
            admin=True,
            active=True,
        )
        db.session.add(user)
        db.session.commit()

        # Tests retain an app context for direct database assertions. Reset the
        # login cache on each request to reproduce real per-request contexts.
        def reset_login_cache(sender, **kwargs):
            g.pop("_login_user", None)

        request_started.connect(reset_login_cache, app)
        yield app.test_client()
        request_started.disconnect(reset_login_cache, app)
        db.session.remove()
        db.drop_all()
        cache.clear()
    app.instance_path = previous_instance


@pytest.fixture
def authenticated(client):
    response = client.post(
        "/ThreatKB/login",
        json={"email": "analyst@example.test", "password": "test-password"},
    )
    assert response.status_code == 200
    assert response.json["result"] is True
    return client


@pytest.fixture
def content_save(authenticated, monkeypatch):
    """Submit through HTTP, then deliver the queued task separately."""
    from app.routes.jobs import execute_job

    monkeypatch.setattr(execute_job, "apply_async", lambda **kwargs: None)

    def save(path, payload, method="POST"):
        source = authenticated.get(
            path if method == "PUT" else "/ThreatKB/content"
        ).json
        payload = {**payload, "revision": source["revision"]}
        if "file_name" in source:
            payload["file_name"] = source["file_name"]
        response = authenticated.open(path, method=method, json=payload)
        assert response.status_code == 202, response.json
        job = execute_job.apply(args=[response.json["id"]]).result
        assert job["status"] == "succeeded", job
        return job["result"]

    return save
