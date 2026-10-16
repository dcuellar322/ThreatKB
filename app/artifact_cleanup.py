"""Transactional cleanup of dependent rows when an artifact is permanently removed."""

from flask import abort
from app import db
from app.models.comments import Comments
from app.models.bookmarks import Bookmarks
from app.models.tags_mapping import Tags_mapping
from app.models.metadata import Metadata, MetadataMapping
from app.models.files import Files


def purge_artifacts(model, kind, identities):
    ids = list(identities)
    stored_files = []
    for start in range(0, len(ids), 500):
        group = ids[start : start + 500]
        if kind == 1:
            from app.models.yara_rule import (
                Yara_rule_history,
                Yara_testing_history,
                Yara_testing_history_files_matches,
            )
            from app.models.releases import ReleaseYaraRuleHistory
            from app.models.scheduled_confidence import ScheduledConfidence

            revisions = db.select(Yara_rule_history.id).where(
                Yara_rule_history.yara_rule_id.in_(group)
            )
            if ReleaseYaraRuleHistory.query.filter(
                ReleaseYaraRuleHistory.yara_rules_history_id.in_(revisions)
            ).first():
                abort(
                    409,
                    description="Published signature history must be retained. Keep these signatures inactive instead of permanently deleting them.",
                )
            tests = db.select(Yara_testing_history.id).where(
                Yara_testing_history.yara_rule_id.in_(group)
            )
            Yara_testing_history_files_matches.query.filter(
                Yara_testing_history_files_matches.history_id.in_(tests)
            ).delete(synchronize_session=False)
            Yara_testing_history.query.filter(
                Yara_testing_history.yara_rule_id.in_(group)
            ).delete(synchronize_session=False)
            ScheduledConfidence.query.filter(
                ScheduledConfidence.rule_id.in_(group)
            ).delete(synchronize_session=False)
            Yara_rule_history.query.filter(
                Yara_rule_history.yara_rule_id.in_(group)
            ).delete(synchronize_session=False)
        Comments.query.filter(
            Comments.entity_type == kind, Comments.entity_id.in_(group)
        ).delete(synchronize_session=False)
        Bookmarks.query.filter(
            Bookmarks.entity_type == kind, Bookmarks.entity_id.in_(group)
        ).delete(synchronize_session=False)
        Tags_mapping.query.filter(
            Tags_mapping.source_table == model.__tablename__,
            Tags_mapping.source_id.in_(group),
        ).delete(synchronize_session=False)
        fields = db.select(Metadata.id).where(Metadata.artifact_type == kind)
        MetadataMapping.query.filter(
            MetadataMapping.metadata_id.in_(fields),
            MetadataMapping.artifact_id.in_(group),
        ).delete(synchronize_session=False)
        from pathlib import Path
        from werkzeug.utils import secure_filename

        for row in Files.query.filter(
            Files.entity_type == kind, Files.entity_id.in_(group)
        ):
            stored_files.append(Path(row.full_path) / secure_filename(row.filename))
        Files.query.filter(
            Files.entity_type == kind, Files.entity_id.in_(group)
        ).delete(synchronize_session=False)
        model.query.filter(model.id.in_(group)).delete(synchronize_session=False)
    db.session.commit()
    for path in stored_files:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            from app import app

            app.logger.warning("Could not remove purged sample file %s", path)
    return len(ids)
