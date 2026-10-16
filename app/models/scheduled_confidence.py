from app import db


class ScheduledConfidence(db.Model):
    __tablename__ = "scheduled_confidence"
    rule_id = db.Column(db.Integer, db.ForeignKey("yara_rules.id"), primary_key=True)
    confidence = db.Column(db.Integer, nullable=False)
    due_at = db.Column(db.DateTime, nullable=False, index=True)
    created_user_id = db.Column(
        db.Integer, db.ForeignKey("kb_users.id"), nullable=False
    )
    applied_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "confidence": self.confidence,
            "due_at": self.due_at.isoformat() + "Z",
            "applied_at": self.applied_at.isoformat() + "Z"
            if self.applied_at
            else None,
        }
