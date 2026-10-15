from datetime import datetime, timezone
from flask import request, jsonify, abort
from flask_login import login_required, current_user
from app import app, db
from app.celeryapp import celery
from app.models.scheduled_confidence import ScheduledConfidence
from app.models.yara_rule import Yara_rule
from app.models.metadata import Metadata, MetadataMapping


@app.route(
    "/ThreatKB/yara_rules/<int:rule_id>/confidence-schedule",
    methods=["GET", "PUT", "DELETE"],
)
@login_required
def confidence_schedule(rule_id):
    rule = db.get_or_404(Yara_rule, rule_id)
    if not current_user.admin and rule.owner_user_id != current_user.id:
        abort(403)
    schedule = db.session.get(ScheduledConfidence, rule_id)
    if request.method == "DELETE":
        if schedule:
            db.session.delete(schedule)
            db.session.commit()
        return "", 204
    if request.method == "PUT":
        data = request.get_json()
        try:
            confidence = int(data["confidence"])
            due = datetime.fromisoformat(data["due_at"].replace("Z", "+00:00"))
            if due.tzinfo is None or not 0 <= confidence <= 100:
                raise ValueError()
        except ValueError, KeyError, TypeError:
            abort(
                400,
                description="Provide confidence 0–100 and a timestamp with a timezone.",
            )
        schedule = schedule or ScheduledConfidence(rule_id=rule_id)
        schedule.confidence = confidence
        schedule.due_at = due.astimezone(timezone.utc).replace(tzinfo=None)
        schedule.created_user_id = current_user.id
        schedule.applied_at = None
        db.session.add(schedule)
        db.session.commit()
    return jsonify(schedule.to_dict() if schedule else None)


def apply_due_confidence(now=None):
    now = now or datetime.now(timezone.utc).replace(tzinfo=None)
    pending = (
        ScheduledConfidence.query.filter(
            ScheduledConfidence.due_at <= now, ScheduledConfidence.applied_at.is_(None)
        )
        .with_for_update()
        .all()
    )
    count = 0
    rules = (
        {
            rule.id: rule
            for rule in Yara_rule.query.filter(
                Yara_rule.id.in_([s.rule_id for s in pending]),
                Yara_rule.active.is_(True),
            )
        }
        if pending
        else {}
    )
    field = (
        Metadata.query.filter(
            Metadata.artifact_type == 1,
            db.func.lower(Metadata.key) == "confidence",
            Metadata.active.is_(True),
        ).first()
        if rules
        else None
    )
    if rules and field is None:
        field = Metadata(
            key="confidence",
            type_="integer",
            artifact_type=1,
            created_user_id=pending[0].created_user_id,
        )
        db.session.add(field)
        db.session.flush()
    mappings = (
        {
            row.artifact_id: row
            for row in MetadataMapping.query.filter(
                MetadataMapping.metadata_id == field.id,
                MetadataMapping.artifact_id.in_(rules),
            )
        }
        if field
        else {}
    )
    for schedule in pending:
        rule = rules.get(schedule.rule_id)
        if rule is None:
            continue
        mapping = mappings.get(rule.id)
        if mapping is None:
            mapping = MetadataMapping(
                metadata_id=field.id,
                artifact_id=rule.id,
                created_user_id=schedule.created_user_id,
            )
        mapping.value = str(schedule.confidence)
        schedule.applied_at = now
        db.session.add(mapping)
        count += 1
    db.session.commit()
    return count


@celery.task(name="threatkb.apply_scheduled_confidence")
def scheduled_confidence_task():
    return apply_due_confidence()


@app.cli.command("apply-scheduled-confidence")
def apply_confidence_command():
    import click

    click.echo(f"Applied {apply_due_confidence()} scheduled changes")
