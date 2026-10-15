def test_significant_metadata_columns_are_preserved_and_discoverable(authenticated):
    response = authenticated.post(
        "/ThreatKB/metadata",
        json={
            "key": "confidence",
            "artifact_type": 1,
            "type": "integer",
            "show_in_table": 1,
        },
    )
    assert response.status_code == 201
    assert response.json["show_in_table"] == 1
    columns = authenticated.get("/ThreatKB/metadata/columns?artifact_type=1")
    assert [field["key"] for field in columns.json] == ["confidence"]
    assert authenticated.get("/ThreatKB/metadata/columns?artifact_type=3").json == []
    assert authenticated.get("/ThreatKB/metadata?artifact_type=1").status_code == 200
