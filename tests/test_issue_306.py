from app import db
from app.models.yara_rule import Yara_rule


def test_restore_retains_rule_identity_and_revision(authenticated):
    db.session.execute(
        Yara_rule.__table__.insert().values(
            name="retired_signature",
            eventid=10001,
            revision=5,
            active=False,
            created_user_id=1,
            modified_user_id=1,
        )
    )
    db.session.commit()
    response = authenticated.post("/ThreatKB/yara_rules/1/restore")
    assert response.status_code == 200
    assert response.json["active"] is True
    assert response.json["revision"] == 5
    assert response.json["eventid"] == 10001
