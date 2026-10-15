from app.routes.import_ import save_artifacts
from app import app, db
from app.models.c2ip import C2ip
from flask_login import login_user
from app.models.users import KBUser


def test_bulk_import_rejects_invalid_ip_and_continues(authenticated):
    with app.test_request_context():
        login_user(db.session.get(KBUser, 1))
        result = save_artifacts(
            True,
            False,
            False,
            [
                {"type": "ip", "artifact": "999.999.999.999"},
                {"type": "ip", "artifact": "192.0.2.42"},
            ],
        )
    assert len(result["errors"]) == 1
    assert [item["ip"] for item in result["committed"]] == ["192.0.2.42"]
    assert C2ip.query.count() == 1
