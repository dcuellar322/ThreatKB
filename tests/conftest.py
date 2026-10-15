import os

os.environ["THREATKB_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["THREATKB_SECRET_KEY"] = "isolated-test-secret"

import pytest
from app import app, db, cache, bcrypt
from app.models.users import KBUser


@pytest.fixture
def client():
    app.config.update(TESTING=True)
    with app.app_context():
        db.create_all()
        cache.clear()
        user = KBUser(email="analyst@example.test", password=bcrypt.generate_password_hash("test-password").decode(),
                      admin=True, active=True)
        db.session.add(user)
        db.session.commit()
        yield app.test_client()
        db.session.remove()
        db.drop_all()
        cache.clear()


@pytest.fixture
def authenticated(client):
    response = client.post("/ThreatKB/login", json={"email": "analyst@example.test", "password": "test-password"})
    assert response.status_code == 200
    assert response.json["result"] is True
    return client
