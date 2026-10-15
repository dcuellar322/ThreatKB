from app import db
from app.models.cfg_states import Cfg_states
from app.models.yara_rule import Yara_rule_history


def test_restore_history_creates_new_revision_and_preserves_audit(authenticated):
    db.session.execute(Cfg_states.__table__.insert().values(state='Vetting'))
    db.session.commit()
    data = {'name': 'restore_history', 'state': 'Vetting', 'condition': 'true', 'description': 'first'}
    assert authenticated.post('/ThreatKB/yara_rules', json=data).status_code == 201
    assert authenticated.put('/ThreatKB/yara_rules/1', json={**data, 'description': 'second'}).status_code == 200
    response = authenticated.post('/ThreatKB/yara_rules/1/revisions/1/restore')
    assert response.status_code == 200
    assert response.json['description'] == 'first'
    assert response.json['revision'] == 3
    assert Yara_rule_history.query.count() == 3
