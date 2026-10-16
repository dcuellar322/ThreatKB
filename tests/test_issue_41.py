import io
from app import db
from app.models.yara_rule import Yara_rule


def test_scan_upload_returns_rule_and_matching_strings(authenticated):
    db.session.execute(
        Yara_rule.__table__.insert().values(
            name="dev_scanner",
            eventid=10001,
            strings='$sample = "THREATKB_TEST"',
            condition="$sample",
            created_user_id=1,
            modified_user_id=1,
        )
    )
    db.session.commit()
    response = authenticated.post(
        "/ThreatKB/scan", data={"file": (io.BytesIO(b"THREATKB_TEST"), "test.bin")}
    )
    assert response.status_code == 200
    assert response.json["matches"][0]["rule"] == "dev_scanner"
    assert response.json["matches"][0]["strings"][0]["instances"][0]["offset"] == 0
    assert authenticated.post("/ThreatKB/scan").status_code == 400
