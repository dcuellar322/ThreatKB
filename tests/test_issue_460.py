from datetime import datetime, timedelta
import json
from app import db
from app.models.c2ip import C2ip
from app.models.cfg_states import Cfg_states


def test_mass_retire_only_existing_released_indicators_and_filter_expired(authenticated):
    db.session.execute(Cfg_states.__table__.insert(), [dict(state='Released', is_release_state=1, is_retired_state=0),
        dict(state='Retired', is_release_state=0, is_retired_state=1)])
    db.session.execute(C2ip.__table__.insert(), [dict(ip='192.0.2.1', state='Released', created_user_id=1,
        modified_user_id=1, expiration_timestamp=datetime.now() - timedelta(days=1)),
        dict(ip='192.0.2.2', state='Vetting', created_user_id=1, modified_user_id=1, expiration_timestamp=None)])
    db.session.commit()
    response = authenticated.post('/ThreatKB/import/commit', json={'retire_existing': True,
        'artifacts': [{'type': 'IP', 'artifact': value} for value in ['192.0.2.1', '192.0.2.2', '192.0.2.3']]})
    assert response.status_code == 201
    assert response.json['artifacts']['retired'] == ['192.0.2.1']
    assert C2ip.query.count() == 2
    assert C2ip.query.filter_by(ip='192.0.2.2').one().state == 'Vetting'
    response = authenticated.get('/ThreatKB/c2ips', query_string={'searches': json.dumps({'expiration_timestamp': '<now'})})
    assert response.status_code == 200
    assert response.json['total_count'] == 1
