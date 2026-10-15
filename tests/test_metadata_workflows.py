from app import db
from app.models.cfg_states import Cfg_states
from app.models.metadata import Metadata, MetadataMapping


def field(client, key, kind, type_="string", **extra):
    response = client.post(
        "/ThreatKB/metadata",
        json={
            "key": key,
            "artifact_type": kind,
            "type": type_,
            **extra,
        },
    )
    assert response.status_code == 201, response.json
    return response.json["id"]


def test_task_metadata_defaults_edit_filter_sort_and_validation(authenticated):
    db.session.add(Cfg_states(state="Review"))
    db.session.commit()
    identity = field(authenticated, "Priority", 4, "integer", default="2")
    field(authenticated, "Deadline", 4, "date")
    response = authenticated.post(
        "/ThreatKB/tasks", json={"title": "Metadata task", "state": "Review"}
    )
    assert response.status_code == 201, response.json
    task = response.json
    assert task["metadata_values"]["Priority"]["value"] == 2
    task["metadata_values"] = {
        "Priority": {"value": "100"},
        "Deadline": {"value": "2027-01-01"},
    }
    response = authenticated.put(f"/ThreatKB/tasks/{task['id']}", json=task)
    assert response.status_code == 200, response.json
    assert response.json["metadata_values"]["Priority"]["value"] == 100
    assert MetadataMapping.query.filter_by(metadata_id=identity).count() == 1
    listing = authenticated.get(
        "/ThreatKB/tasks",
        query_string={
            "searches": '{"Priority":{"op":"eq","value":"100"}}',
            "sort_by": "metadata:Priority",
        },
    )
    assert listing.status_code == 200, listing.json
    assert listing.json["total_count"] == 1
    assert listing.json["data"][0]["metadata_values"]["Priority"]["value"] == 100
    task["metadata_values"] = {"Priority": {"value": "1.5"}}
    assert (
        authenticated.put(f"/ThreatKB/tasks/{task['id']}", json=task).status_code == 400
    )
    db.session.rollback()
    task["metadata_values"] = {"Deadline": {"value": "not-a-date"}}
    assert (
        authenticated.put(f"/ThreatKB/tasks/{task['id']}", json=task).status_code == 400
    )


def test_deactivated_signature_metadata_does_not_block_edit(authenticated):
    db.session.add(Cfg_states(state="Review"))
    db.session.commit()
    identity = field(authenticated, "Archived", 1)
    response = authenticated.post(
        "/ThreatKB/yara_rules",
        json={
            "name": "ArchivedMetadata",
            "state": "Review",
            "condition": "true",
            "metadata_values": {"Archived": {"value": "retain this value"}},
        },
    )
    assert response.status_code == 201, response.json
    task = response.json
    assert authenticated.delete(f"/ThreatKB/metadata/{identity}").status_code == 204
    response = authenticated.put(
        f"/ThreatKB/yara_rules/{task['id']}",
        json={"description": "Edited after deactivation"},
    )
    assert response.status_code == 200, response.json
    assert (
        MetadataMapping.query.filter_by(metadata_id=identity).one().value
        == "retain this value"
    )
    assert (
        authenticated.put(
            f"/ThreatKB/metadata/{identity}", json={"active": True}
        ).status_code
        == 200
    )
    assert (
        authenticated.get(f"/ThreatKB/yara_rules/{task['id']}").json["metadata_values"][
            "Archived"
        ]["value"]
        == "retain this value"
    )


def test_repeated_ip_metadata_edit_updates_existing_mapping(authenticated):
    db.session.add(Cfg_states(state="Review"))
    db.session.commit()
    identity = field(authenticated, "IPNotes", 3)
    response = authenticated.post(
        "/ThreatKB/c2ips",
        json={
            "ip": "2001:db8::ab",
            "asn": "",
            "state": "Review",
            "tags": [],
            "metadata_values": {"IPNotes": {"value": "first"}},
        },
    )
    assert response.status_code == 201, response.json
    value = response.json
    value["metadata_values"] = {"IPNotes": {"value": "second"}}
    response = authenticated.put(f"/ThreatKB/c2ips/{value['id']}", json=value)
    assert response.status_code == 200, response.json
    assert response.json["metadata_values"]["IPNotes"]["value"] == "second"
    assert MetadataMapping.query.filter_by(metadata_id=identity).count() == 1
