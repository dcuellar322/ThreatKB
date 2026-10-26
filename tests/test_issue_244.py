from app import db, bcrypt
from app.models.users import KBUser
from app.models.access_keys import AccessKeys


def test_deactivation_revokes_sessions_and_tokens(authenticated):
    user = KBUser(
        email="retiring@example.test",
        password=bcrypt.generate_password_hash("retiring").decode(),
        admin=False,
        active=True,
    )
    db.session.add(user)
    db.session.flush()
    user_id = user.id
    key = AccessKeys(user_id=user_id, token="retiring-test-token")
    db.session.add(key)
    db.session.commit()
    key_id = key.id
    other_client = authenticated.application.test_client()
    assert (
        other_client.post(
            "/ThreatKB/login", json={"email": user.email, "password": "retiring"}
        ).status_code
        == 200
    )
    assert authenticated.delete(f"/ThreatKB/users/{user_id}").status_code == 204
    assert other_client.get("/ThreatKB/users/me").status_code == 401
    assert db.session.get(AccessKeys, key_id).status == "inactive"
    assert authenticated.delete("/ThreatKB/users/1").status_code == 409
