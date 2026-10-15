from app import db
from app.models.yara_rule import Yara_rule
from app.routes.test_yara_rule import test_yara_rule as run_rule_test


def test_lost_sample_matches_are_persisted_and_ghosted(authenticated, tmp_path):
    db.session.execute(Yara_rule.__table__.insert().values(name='sample_regression', eventid=10001,
        condition='$marker', strings='$marker = "SYNTHETIC_MARKER"', created_user_id=1, modified_user_id=1))
    db.session.commit()
    matching, unmatched = tmp_path / 'matching.bin', tmp_path / 'unmatched.bin'
    matching.write_bytes(b'SYNTHETIC_MARKER')
    unmatched.write_bytes(b'ordinary benign content')
    rule = db.session.get(Yara_rule, 1)
    assert run_rule_test(rule, [str(matching), str(unmatched)], 1)['files_matched'] == 1
    matching.write_bytes(b'changed benign content')
    assert run_rule_test(rule, [str(matching), str(unmatched)], 1)['files_matched'] == 0
    response = authenticated.get('/ThreatKB/yara_rules/1/sample-results')
    assert response.status_code == 200
    assert len(response.json['files']) == 1
    assert response.json['files'][0]['status'] == 'regressed'
    assert len(authenticated.get('/ThreatKB/yara_rules/1/sample-results?show_all=true').json['files']) == 2
