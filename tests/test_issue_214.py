from app import db
from app.models.metadata import MetadataMapping


def test_edit_enum_and_protect_existing_values(authenticated):
    response = authenticated.post('/ThreatKB/metadata', json={
        'key': 'verdict', 'artifact_type': 1, 'type': 'select', 'choices': 'low,high'})
    assert response.status_code == 201
    field_id = response.json['id']
    path = f'/ThreatKB/metadata/{field_id}'
    response = authenticated.put(path, json={'choices': ['low', 'high', 'unknown']})
    assert response.status_code == 200
    assert len(response.json['choices']) == 3
    db.session.add(MetadataMapping(metadata_id=field_id, artifact_id=1, value='low', created_user_id=1))
    db.session.commit()
    assert authenticated.put(path, json={'choices': ['high']}).status_code == 409
