from datetime import datetime, timezone
import json
from pathlib import Path
import yaml
from app import app
from app.content_alerts import unread_content_alarms
from app.models.users import KBUser


def test_content_alarm_visibility_cursor_and_production_resolution(
    authenticated, tmp_path
):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "policies.yaml").write_text(
        yaml.safe_dump({"groups": {"default": {"members": ["1"]}}})
    )
    previous = app.config.get("CONTENT_REPOSITORY")
    app.config["CONTENT_REPOSITORY"] = str(root)
    try:
        path = Path(app.instance_path) / "channels/sigpack/default/testing.json"
        path.parent.mkdir(parents=True)
        state = {
            "manifest": {"id": "fixture", "group": "default", "kind": "sigpack"},
            "status": "testing",
            "promotion_block": {
                "alarm": True,
                "message": "Telemetry alarm blocks production promotion",
                "since": datetime.now(timezone.utc).isoformat(),
            },
        }
        path.write_text(json.dumps(state))
        response = authenticated.get("/ThreatKB/notifications")
        assert response.status_code == 200 and response.json["unread_count"] == 1
        assert "Telemetry alarm" in response.json["data"][0]["activity_text"]
        assert unread_content_alarms(KBUser(id=2, admin=False)) == []
        assert (
            authenticated.post("/ThreatKB/notifications/clear").json["unread_count"]
            == 0
        )
        assert (
            authenticated.get("/ThreatKB/notifications?summary=true").json[
                "unread_count"
            ]
            == 0
        )
        path.with_name("production.json").write_text(json.dumps(state))
        assert unread_content_alarms(KBUser(id=3, admin=True)) == []
    finally:
        if previous is None:
            app.config.pop("CONTENT_REPOSITORY", None)
        else:
            app.config["CONTENT_REPOSITORY"] = previous
