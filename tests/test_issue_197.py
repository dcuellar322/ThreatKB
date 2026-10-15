from app import db
from app.models.cfg_settings import Cfg_settings
from app.models.cfg_states import Cfg_states
from app.models.whitelist import Whitelist


def test_misp_import_is_repeatable_and_matches_domain_boundaries(authenticated):
    document = {'name': 'Known service domains', 'version': 1, 'type': 'hostname', 'list': ['.example.com']}
    assert authenticated.post('/ThreatKB/whitelist/import-misp', json=document).json['added'] == 1
    assert authenticated.post('/ThreatKB/whitelist/import-misp', json=document).json['added'] == 0
    db.session.add_all([Cfg_settings(key='ENABLE_IP_WHITELIST_CHECK_ON_SAVE', value='true'),
                        Cfg_settings(key='WHITELIST_STATES', value='Released')])
    db.session.execute(Cfg_states.__table__.insert().values(state='Released', is_release_state=1))
    db.session.commit()
    assert Whitelist.hits_whitelist('mail.example.com', 'Released')
    assert not Whitelist.hits_whitelist('example.com.evil.test', 'Released')
    assert not Whitelist.hits_whitelist('notexample.com', 'Released')
