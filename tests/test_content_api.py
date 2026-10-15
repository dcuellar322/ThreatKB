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


def test_feed_export_selects_only_active_released_indicators(authenticated, tmp_path):
    from app import db
    from app.models.c2ip import C2ip
    from app.models.cfg_states import Cfg_states
    from threatkb_content.engine import load, Repository

    previous = app.config.get("CONTENT_REPOSITORY")
    root = tmp_path / "content"
    app.config["CONTENT_REPOSITORY"] = str(root)
    try:
        db.session.add(Cfg_states(state="Released", is_release_state=1))
        db.session.add_all(
            [
                C2ip(
                    ip="192.0.2.21",
                    state="Released",
                    created_user_id=1,
                    modified_user_id=1,
                ),
                C2ip(
                    ip="192.0.2.22",
                    state="Vetting",
                    created_user_id=1,
                    modified_user_id=1,
                ),
            ]
        )
        from flask_login import login_user
        from app.models.users import KBUser

        with app.test_request_context():
            with db.session.no_autoflush:
                login_user(db.session.get(KBUser, 1))
            db.session.commit()
        response = authenticated.post("/ThreatKB/content/export-indicators", json={})
        assert response.status_code == 200, response.json
        assert response.json["exported"] == 1
        assert load(root / "indicators.yaml")[0]["value"] == "192.0.2.21"
        assert (
            Repository(root, load_rules=False).build(
                tmp_path / "builds", kind="feedpack"
            )["indicators"]
            == 1
        )
    finally:
        if previous is None:
            app.config.pop("CONTENT_REPOSITORY", None)
        else:
            app.config["CONTENT_REPOSITORY"] = previous
