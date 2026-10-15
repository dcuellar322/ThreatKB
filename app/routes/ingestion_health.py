import json
import re
from flask import request, jsonify, abort
from flask_login import login_required
from app import app, db, admin_only
from app.ingestion_health import PREFIX, ingestion_health, record_ingestion_success
from app.models.cfg_settings import Cfg_settings


@app.get("/ThreatKB/ingestion/health")
@login_required
def get_ingestion_health():
    return jsonify(ingestion_health())


@app.post("/ThreatKB/ingestion/monitors")
@login_required
@admin_only()
def configure_ingestion_monitor():
    data = request.get_json()
    name, delay = data.get("name"), data.get("max_delay_minutes", 60)
    if (
        not isinstance(name, str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name)
        or type(delay) is not int
        or not 1 <= delay <= 10080
    ):
        abort(
            400, description="Provide a source name and delay from 1 to 10080 minutes."
        )
    setting = db.session.get(Cfg_settings, PREFIX + name)
    monitor = json.loads(setting.value) if setting else {"name": name}
    monitor.update(max_delay_minutes=delay, enabled=bool(data.get("enabled", True)))
    if setting is None:
        setting = Cfg_settings(
            key=PREFIX + name, public=False, description="Ingestion freshness monitor"
        )
        db.session.add(setting)
    setting.value = json.dumps(monitor)
    db.session.commit()
    return jsonify(monitor)


@app.post("/ThreatKB/ingestion/heartbeat")
@login_required
def ingestion_heartbeat():
    data = request.get_json()
    try:
        return jsonify(
            record_ingestion_success(data.get("source"), int(data.get("count", 0)))
        )
    except (TypeError, ValueError) as error:
        abort(400, description=str(error))
