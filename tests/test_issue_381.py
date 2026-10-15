from app import db
from app.models.cfg_states import Cfg_states
from app.models.yara_rule import Yara_rule_history


def test_restore_history_creates_new_revision_and_preserves_audit(authenticated):
    db.session.execute(Cfg_states.__table__.insert().values(state="Vetting"))
    db.session.commit()
    data = {
        "name": "restore_history",
        "state": "Vetting",
        "condition": "true",
        "description": "first",
    }
    assert authenticated.post("/ThreatKB/yara_rules", json=data).status_code == 201
    assert (
        authenticated.put(
            "/ThreatKB/yara_rules/1", json={**data, "description": "second"}
        ).status_code
        == 200
    )
    response = authenticated.post("/ThreatKB/yara_rules/1/revisions/1/restore")
    assert response.status_code == 200
    assert response.json["description"] == "first"
    assert response.json["revision"] == 3
    assert Yara_rule_history.query.count() == 3


def test_kept_revision_uses_latest_snapshot_for_comparison_and_restore(authenticated):
    db.session.add(Cfg_states(state="Vetting"))
    db.session.commit()
    data = {
        "name": "kept_revision",
        "state": "Vetting",
        "condition": "true",
        "description": "original",
    }
    created = authenticated.post("/ThreatKB/yara_rules", json=data)
    assert created.status_code == 201
    kept = authenticated.put(
        "/ThreatKB/yara_rules/1",
        json={
            **data,
            "condition": "false",
            "description": "latest within revision",
            "do_not_bump_revision": True,
        },
    )
    assert kept.status_code == 200
    assert kept.json["revision"] == 1
    source = authenticated.get("/ThreatKB/yara_rules/1/revision/1")
    assert source.status_code == 200
    assert "condition:\nfalse" in source.json
    bumped = authenticated.put("/ThreatKB/yara_rules/1", json=data)
    assert bumped.status_code == 200
    assert bumped.json["revision"] == 2
    restored = authenticated.post("/ThreatKB/yara_rules/1/revisions/1/restore")
    assert restored.status_code == 200
    assert restored.json["condition"].split("condition:", 1)[-1].strip() == "false"
    assert restored.json["description"] == "latest within revision"
    assert restored.json["revision"] == 3
    assert Yara_rule_history.query.count() == 4
