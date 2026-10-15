from app import db
from app.models.cfg_states import Cfg_states
from app.models.yara_rule import Yara_rule_history


def test_noop_save_keeps_revision_but_content_change_increments(authenticated):
    db.session.execute(
        Cfg_states.__table__.insert().values(state="Vetting", is_staging_state=1)
    )
    db.session.commit()
    payload = {
        "name": "stable_revision",
        "category": "Uncategorized",
        "state": "Vetting",
        "strings": '$a = "benign"',
        "condition": "$a",
        "tags": [],
    }
    created = authenticated.post("/ThreatKB/yara_rules", json=payload)
    assert created.status_code == 201
    rule_id = created.json["id"]
    saved = authenticated.put(f"/ThreatKB/yara_rules/{rule_id}", json=payload)
    assert saved.status_code == 200
    assert saved.json["revision"] == 1
    payload["description"] = "Actual content change"
    saved = authenticated.put(f"/ThreatKB/yara_rules/{rule_id}", json=payload)
    assert saved.status_code == 200
    assert saved.json["revision"] == 2
    assert Yara_rule_history.query.count() == 2
