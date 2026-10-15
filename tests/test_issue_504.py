from datetime import timedelta
from app.ingestion_health import ingestion_health, utcnow


def test_stale_ingestion_alert_clears_after_heartbeat(authenticated):
    assert (
        authenticated.post(
            "/ThreatKB/ingestion/monitors",
            json={"name": "automated-feed", "max_delay_minutes": 15},
        ).status_code
        == 200
    )
    assert (
        authenticated.get("/ThreatKB/ingestion/health").json["alerts"][0]["name"]
        == "automated-feed"
    )
    assert (
        authenticated.post(
            "/ThreatKB/ingestion/heartbeat",
            json={"source": "automated-feed", "count": 12},
        ).status_code
        == 200
    )
    assert authenticated.get("/ThreatKB/ingestion/health").json["healthy"] is True
    assert (
        ingestion_health(utcnow() + timedelta(minutes=16))["alerts"][0]["last_count"]
        == 12
    )
