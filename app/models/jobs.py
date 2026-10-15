from uuid import uuid4
from datetime import datetime, timezone
from app import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Job(db.Model):
    __tablename__ = "background_jobs"
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid4()))
    kind = db.Column(db.String(64), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="queued", index=True)
    payload = db.Column(db.JSON, nullable=False, default=dict)
    result = db.Column(db.JSON)
    error = db.Column(db.Text)
    progress = db.Column(db.Integer, nullable=False, default=0)
    created_user_id = db.Column(
        db.Integer, db.ForeignKey("kb_users.id"), nullable=False, index=True
    )
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    started_at = db.Column(db.DateTime)
    finished_at = db.Column(db.DateTime)

    def to_dict(self):
        result = {
            key: getattr(self, key)
            for key in (
                "id",
                "kind",
                "status",
                "payload",
                "result",
                "error",
                "progress",
                "created_user_id",
            )
        }
        for key in ("created_at", "started_at", "finished_at"):
            value = getattr(self, key)
            result[key] = value.isoformat() + "Z" if value else None
        return result
