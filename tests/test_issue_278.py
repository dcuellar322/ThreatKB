from app import db
from app.models.yara_rule import Yara_rule
from app.models.comments import Comments
from app.models.cfg_states import Cfg_states


def test_artifact_save_includes_unsent_comment_without_new_revision(authenticated):
    db.session.execute(Cfg_states.__table__.insert().values(state='Vetting'))
    db.session.commit()
    data = {'name': 'draft_comment_rule', 'state': 'Vetting', 'condition': 'true', 'tags': []}
    assert authenticated.post('/ThreatKB/yara_rules', json=data).status_code == 201
    response = authenticated.put('/ThreatKB/yara_rules/1', json={**data, 'new_comment': 'Review note still in draft'})
    assert response.status_code == 200
    assert response.json['revision'] == 1
    assert Comments.query.one().comment == 'Review note still in draft'
