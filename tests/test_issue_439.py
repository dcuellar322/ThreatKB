from app import db
from app.models.yara_rule import Yara_rule
from app.models.cfg_states import Cfg_states
from app.detection import compile_active_rules


def test_save_compiles_with_referenced_released_rules(authenticated):
    db.session.execute(Cfg_states.__table__.insert(), [dict(state='Released', is_release_state=1),
                                                      dict(state='Vetting', is_release_state=0)])
    db.session.execute(Yara_rule.__table__.insert().values(name='released_base', eventid=10001,
        state='Released', condition='true', created_user_id=1, modified_user_id=1))
    db.session.commit()
    response = authenticated.post('/ThreatKB/yara_rules', json={
        'name': 'dependent', 'state': 'Vetting', 'condition': 'released_base', 'strings': ''})
    assert response.status_code == 201
    assert {match.rule for match in compile_active_rules().match(data=b'benign')} == {'released_base', 'dependent'}
    response = authenticated.post('/ThreatKB/yara_rules', json={
        'name': 'broken_reference', 'state': 'Vetting', 'condition': 'missing_rule'})
    assert response.status_code == 422
