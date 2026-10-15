"""Composite indexes matching artifact list, lookup and history query shapes."""

from app import db

PERFORMANCE_INDEXES = []
for table, date in [
    ("yara_rules", "creation_date"),
    ("c2ip", "date_created"),
    ("c2dns", "date_created"),
    ("tasks", "date_created"),
]:
    PERFORMANCE_INDEXES.extend(
        [
            (f"ix_{table}_active_date", table, ("active", date, "id")),
            (f"ix_{table}_active_state_date", table, ("active", "state", date, "id")),
            (
                f"ix_{table}_owner_active_date",
                table,
                ("owner_user_id", "active", date, "id"),
            ),
        ]
    )
PERFORMANCE_INDEXES += [
    ("ix_activity_date", "activity_log", ("activity_date", "id")),
    (
        "ix_activity_artifact_date",
        "activity_log",
        ("entity_type", "entity_id", "activity_date"),
    ),
    ("ix_comments_artifact", "comments", ("entity_type", "entity_id", "id")),
    ("ix_metadata_artifact_active", "metadata", ("artifact_type", "active", "key")),
    (
        "ix_metadata_mapping_artifact",
        "metadata_mapping",
        ("artifact_id", "metadata_id"),
    ),
    (
        "ix_tags_mapping_artifact_tag",
        "tags_mapping",
        ("source_table", "source_id", "tag_id"),
    ),
    (
        "ix_tags_mapping_tag_artifact",
        "tags_mapping",
        ("tag_id", "source_table", "source_id"),
    ),
    (
        "ix_bookmarks_user_artifact",
        "bookmarks",
        ("user_id", "entity_type", "entity_id"),
    ),
    ("ix_rule_history_revision", "yara_rules_history", ("yara_rule_id", "revision")),
    (
        "ix_rule_history_date",
        "yara_rules_history",
        ("yara_rule_id", "date_created", "id"),
    ),
    (
        "ix_test_history_type",
        "yara_testing_history",
        ("yara_rule_id", "test_type", "id"),
    ),
    ("ix_jobs_owner_date", "background_jobs", ("created_user_id", "created_at", "id")),
    ("ix_jobs_created", "background_jobs", ("created_at", "id")),
]
for name, table, columns in PERFORMANCE_INDEXES:
    db.Index(name, *(db.metadata.tables[table].c[column] for column in columns))
