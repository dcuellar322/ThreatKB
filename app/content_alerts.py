"""Actionable content promotion alarms, scoped to the analyst's policy groups."""

import json
from app import app, db
from app.models.cfg_settings import Cfg_settings

CURSOR_PREFIX = "CONTENT_ALERT_CURSOR:"


def unread_content_alarms(user):
    from app.routes.content import channels, repository

    paths = list(channels().glob("*/*/testing.json"))
    if not paths:
        return []
    cursor = db.session.get(Cfg_settings, CURSOR_PREFIX + str(user.id))
    after = cursor.value if cursor else ""
    groups = repository().groups
    alerts = []
    for path in paths:
        try:
            state = json.loads(path.read_text())
            block = state.get("promotion_block", {})
            group = state["manifest"]["group"]
            members = list(map(str, groups.get(group, {}).get("members", [])))
            if group not in groups or (
                members and not user.admin and str(user.id) not in members
            ):
                continue
            if not block.get("alarm") or block["since"] <= after:
                continue
            production = path.with_name("production.json")
            if (
                production.exists()
                and json.loads(production.read_text())["manifest"]["id"]
                == state["manifest"]["id"]
            ):
                continue
            alerts.append(
                {
                    "id": "content-alarm:" + state["manifest"]["id"],
                    "activity_text": f"{state['manifest']['kind']} / {group}: {block['message']}",
                    "activity_date": block["since"],
                    "user": None,
                }
            )
        except ValueError, KeyError, OSError:
            app.logger.warning("Could not read content alarm state at %s", path)
    return sorted(alerts, key=lambda alert: alert["activity_date"], reverse=True)
