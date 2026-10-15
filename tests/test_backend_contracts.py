from app import db, bcrypt
from app.models.users import KBUser


def test_non_admin_cannot_grant_self_administrator(client):
    db.session.add(
        KBUser(
            email="limited@example.test",
            password=bcrypt.generate_password_hash("limited").decode(),
            active=True,
            admin=False,
        )
    )
    db.session.commit()
    assert (
        client.post(
            "/ThreatKB/login",
            json={"email": "limited@example.test", "password": "limited"},
        ).status_code
        == 200
    )
    assert (
        client.put(
            "/ThreatKB/users/2",
            json={"email": "limited@example.test", "admin": True, "active": True},
        ).status_code
        == 403
    )


def test_search_requires_authentication_and_sort_columns_are_validated(
    client, authenticated
):
    assert (
        client.application.test_client().get("/ThreatKB/search?all=test").status_code
        == 401
    )
    assert (
        authenticated.get("/ThreatKB/yara_rules?sort_by=id;SELECT").status_code == 400
    )
    assert authenticated.get("/ThreatKB/search?all=test&limit=-1").status_code == 400


def test_programmatic_header_authentication_and_revocation(authenticated):
    from app.models.access_keys import AccessKeys

    key = authenticated.post("/ThreatKB/access_keys", json={}).json
    caller = authenticated.application.test_client()
    headers = {
        "Authorization": "Bearer " + key["token"],
        "X-ThreatKB-Secret": key["s_key"],
    }
    assert caller.get("/ThreatKB/users/me", headers=headers).status_code == 200
    db.session.execute(
        db.update(AccessKeys)
        .where(AccessKeys.token == key["token"])
        .values(status="inactive")
    )
    db.session.commit()
    assert caller.get("/ThreatKB/users/me", headers=headers).status_code == 401
