def test_ingestion_applies_rich_context_tags(authenticated):
    response = authenticated.post("/ThreatKB/import", json={
        "import_text": "rule imported_tagged { condition: true }", "autocommit": True,
        "extract_ip": False, "extract_dns": False,
        "tags": ["source:community", {"text": "attack:tactic=execution"}],
    })
    assert response.status_code == 200
    result = response.json["artifacts"]
    assert result["errors"] == []
    assert {tag["text"] for tag in result["committed"][0]["tags"]} == {
        "source:community", "attack:tactic=execution"}
