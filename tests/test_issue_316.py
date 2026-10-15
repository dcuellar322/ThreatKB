import yara
from app.models.yara_rule import Yara_rule


def test_unicode_and_quoted_metadata_survive_materialization(client):
    values = {'name': 'unicode_rule', 'description': 'Résumé… "quoted"\nsecond line',
              'strings': '$a = "résumé"', 'condition': '$a'}
    source = Yara_rule.to_yara_rule_string(values)
    assert values['description'] == 'Résumé… "quoted"\nsecond line'
    assert 'Résumé…' in source
    assert yara.compile(source=source).match(data='résumé'.encode())
    assert 'résumé' in Yara_rule.make_yara_sane(values['strings'], 'strings:')
