from app import app


def test_git_content_create_update_and_immutable_uuid(authenticated, tmp_path):
    previous = app.config.get("CONTENT_REPOSITORY")
    app.config["CONTENT_REPOSITORY"] = str(tmp_path / "content")
    try:
        assert authenticated.get("/ThreatKB/content").status_code == 200
        created = authenticated.post(
            "/ThreatKB/content/rules", json={"name": "WebFixture", "category": "UC"}
        )
        assert created.status_code == 201, created.json
        value = created.json
        source = value["yaml"].replace("condition: 'false'", "condition: 'true'")
        updated = authenticated.put(
            "/ThreatKB/content/rules/" + value["id"],
            json={"yaml": source + "\n# Reviewed locally\n"},
        )
        assert updated.status_code == 200, updated.json
        assert len(updated.json["history"]) == 2
        invalid = authenticated.put(
            "/ThreatKB/content/rules/" + value["id"],
            json={
                "yaml": source.replace(
                    value["id"], "4e9a971a-d85b-4e8f-97c1-7daa770b1ad9"
                )
            },
        )
        assert invalid.status_code == 409
        assert (
            authenticated.post("/ThreatKB/content/review", json={}).status_code == 409
        )
    finally:
        if previous is None:
            app.config.pop("CONTENT_REPOSITORY", None)
        else:
            app.config["CONTENT_REPOSITORY"] = previous
