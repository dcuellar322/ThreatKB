from sqlalchemy.event import listens_for
from sqlalchemy.orm import Session

from app import db, ENTITY_MAPPING, ACTIVITY_TYPE
from app.models import activity_log
from app.models.comments import Comments


class Tasks(db.Model):
    __tablename__ = "tasks"

    id = db.Column(db.Integer, primary_key=True)
    date_created = db.Column(
        db.DateTime(timezone=True), default=db.func.current_timestamp()
    )
    date_modified = db.Column(
        db.DateTime(timezone=True),
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )
    state = db.Column(db.String(32), index=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    title = db.Column(db.String(256), index=True)
    description = db.Column(db.TEXT(), index=True)
    final_artifact = db.Column(db.String(4096))

    created_user_id = db.Column(
        db.Integer, db.ForeignKey("kb_users.id"), nullable=False
    )
    created_user = db.relationship(
        "KBUser",
        foreign_keys=created_user_id,
        primaryjoin="KBUser.id==Tasks.created_user_id",
    )

    modified_user_id = db.Column(
        db.Integer, db.ForeignKey("kb_users.id"), nullable=False
    )
    modified_user = db.relationship(
        "KBUser",
        foreign_keys=modified_user_id,
        primaryjoin="KBUser.id==Tasks.modified_user_id",
    )

    owner_user_id = db.Column(db.Integer, db.ForeignKey("kb_users.id"), nullable=True)
    owner_user = db.relationship(
        "KBUser",
        foreign_keys=owner_user_id,
        primaryjoin="KBUser.id==Tasks.owner_user_id",
    )

    comments = db.relationship(
        "Comments",
        foreign_keys="Comments.entity_id",
        viewonly=True,
        primaryjoin="and_(Comments.entity_id==Tasks.id, Comments.entity_type=='%s')"
        % (ENTITY_MAPPING["TASK"]),
    )

    def to_dict(
        self, include_comments=True, users_cache=None,
        include_tags=True, include_metadata=True,
    ):
        task = dict(
            active=self.active,
            date_created=self.date_created.isoformat(),
            date_modified=self.date_modified.isoformat(),
            state=self.state,
            title=self.title,
            description=self.description,
            final_artifact=self.final_artifact,
            id=self.id,
            created_user=users_cache.get(self.created_user_id)
            if users_cache is not None
            else self.created_user.to_dict(),
            modified_user=users_cache.get(self.modified_user_id)
            if users_cache is not None
            else self.modified_user.to_dict(),
            owner_user=users_cache.get(self.owner_user_id)
            if users_cache is not None
            else (self.owner_user.to_dict() if self.owner_user else None),
        )

        if include_tags:
            from app.models.tags import Tags
            from app.models.tags_mapping import Tags_mapping

            task["tags"] = list(db.session.scalars(
                db.select(Tags.text)
                .join(Tags_mapping, Tags_mapping.tag_id == Tags.id)
                .where(
                    Tags_mapping.source_table == "tasks",
                    Tags_mapping.source_id == self.id,
                )
                .order_by(Tags.text)
            ))
        if include_metadata:
            from app.models.metadata import Metadata, MetadataMapping

            task["metadata"] = Metadata.get_metadata_dict("TASK")
            task["metadata_values"] = {
                field.key: mapping.to_dict()
                for mapping, field in db.session.query(MetadataMapping, Metadata)
                .join(Metadata)
                .filter(
                    Metadata.active.is_(True), Metadata.artifact_type == 4,
                    MetadataMapping.artifact_id == self.id,
                )
            }
        if include_comments:
            task["comments"] = [
                comment.to_dict()
                for comment in Comments.query.filter_by(entity_id=self.id)
                .filter_by(entity_type=ENTITY_MAPPING["TASK"])
                .all()
            ]

        return task

    def __repr__(self):
        return "<Tasks %r>" % self.id


@listens_for(Tasks, "after_insert")
def task_created(mapper, connection, target):
    activity_log.log_activity(
        connection=connection,
        activity_type=list(ACTIVITY_TYPE.keys())[
            list(ACTIVITY_TYPE.keys()).index("ARTIFACT_CREATED")
        ],
        activity_text=target.title,
        activity_date=target.date_created,
        entity_type=ENTITY_MAPPING["TASK"],
        entity_id=target.id,
        user_id=target.created_user_id,
    )


@listens_for(Tasks, "after_update")
def task_modified(mapper, connection, target):
    session = Session.object_session(target)

    if session.is_modified(target, include_collections=False):
        state_activity_text = activity_log.get_state_change(target, target.title)
        if state_activity_text:
            activity_log.log_activity(
                connection=connection,
                activity_type=list(ACTIVITY_TYPE.keys())[
                    list(ACTIVITY_TYPE.keys()).index("STATE_TOGGLED")
                ],
                activity_text=state_activity_text,
                activity_date=target.date_modified,
                entity_type=ENTITY_MAPPING["TASK"],
                entity_id=target.id,
                user_id=target.modified_user_id,
            )

        changes = activity_log.get_modified_changes(target)
        if changes.__len__() > 0:
            activity_log.log_activity(
                connection=connection,
                activity_type=list(ACTIVITY_TYPE.keys())[
                    list(ACTIVITY_TYPE.keys()).index("ARTIFACT_MODIFIED")
                ],
                activity_text="'%s' modified with changes: %s"
                % (target.title, ", ".join(map(str, changes))),
                activity_date=target.date_modified,
                entity_type=ENTITY_MAPPING["TASK"],
                entity_id=target.id,
                user_id=target.modified_user_id,
            )
