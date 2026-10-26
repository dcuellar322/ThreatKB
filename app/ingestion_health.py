from datetime import datetime, timezone
import json
import re
from app import db
from app.models.cfg_settings import Cfg_settings

PREFIX = "INGESTION_MONITOR:"


def utcnow():
    return datetime.now(timezone.utc)


def record_ingestion_success(source, count, commit=True):
    if not isinstance(source, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", source):
        raise ValueError("Invalid ingestion source name.")
    key = PREFIX + source
    setting = db.session.get(Cfg_settings, key)
    monitor = (
        json.loads(setting.value)
        if setting
        else {"name": source, "max_delay_minutes": 60, "enabled": True}
    )
    monitor.update(last_success=utcnow().isoformat(), last_count=count)
    if setting is None:
        setting = Cfg_settings(
            key=key, public=False, description="Ingestion freshness monitor"
        )
        db.session.add(setting)
    setting.value = json.dumps(monitor)
    if commit:
        db.session.commit()
    return monitor


def ingestion_health(now=None):
    now = now or utcnow()
    monitors = []
    for setting in Cfg_settings.query.filter(Cfg_settings.key.like(PREFIX + "%")):
        monitor = json.loads(setting.value)
        last = (
            datetime.fromisoformat(monitor["last_success"])
            if monitor.get("last_success")
            else None
        )
        age = max(0, (now - last).total_seconds() / 60) if last else None
        stale = bool(
            monitor.get("enabled", True)
            and (age is None or age > monitor["max_delay_minutes"])
        )
        monitors.append(
            {
                **monitor,
                "age_minutes": round(age, 1) if age is not None else None,
                "stale": stale,
            }
        )
    return {
        "monitors": monitors,
        "alerts": [item for item in monitors if item["stale"]],
        "healthy": not any(item["stale"] for item in monitors),
    }
