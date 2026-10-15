from datetime import datetime
from app import db
from app.models.activity_log import ActivityLog


def test_activity_distribution_counts_and_shares(authenticated):
    db.session.execute(
        ActivityLog.__table__.insert(),
        [
            dict(
                activity_type="COMMENTS",
                activity_text="review",
                activity_date=datetime.now(),
                entity_type=1,
                entity_id=1,
                user_id=user_id,
            )
            for user_id in [1, 1, None]
        ],
    )
    db.session.commit()
    response = authenticated.get("/ThreatKB/activity_log/distribution")
    assert response.status_code == 200
    assert response.json["total"] == 3
    assert response.json["users"][0]["count"] == 2
    assert response.json["users"][0]["percent"] == 66.67
