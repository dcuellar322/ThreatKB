from app import db
from app.models.yara_rule import Yara_rule
from app.models.metadata import MetadataMapping
from app.routes.scheduled_confidence import apply_due_confidence


def test_confidence_is_scheduled_applied_once_and_cancelable(authenticated):
    db.session.execute(
        Yara_rule.__table__.insert().values(
            name="scheduled", eventid=10001, created_user_id=1, modified_user_id=1
        )
    )
    db.session.commit()
    path = "/ThreatKB/yara_rules/1/confidence-schedule"
    assert (
        authenticated.put(
            path, json={"confidence": 90, "due_at": "2020-01-01T00:00:00Z"}
        ).status_code
        == 200
    )
    assert apply_due_confidence() == 1
    assert apply_due_confidence() == 0
    assert MetadataMapping.query.one().value == "90"
    assert authenticated.delete(path).status_code == 204
    assert authenticated.get(path).json is None
