from app import db
from . import yara_rule
from sqlalchemy import bindparam, text


class CfgCategoryRangeMapping(db.Model):
    __tablename__ = "cfg_category_range_mapping"

    DEFAULT_CATEGORY = "Uncategorized"
    COMMITTED_DEFAULT = None

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    category = db.Column(db.String(255), unique=True, nullable=False)
    range_min = db.Column(db.Integer(), index=True, nullable=False)
    range_max = db.Column(db.Integer(), index=True, nullable=False)
    current = db.Column(db.Integer(), index=True, nullable=True)
    include_in_release_notes = db.Column(db.Boolean, nullable=False, default=True, index=True)

    def to_dict(self, include_inactive=False):

        if include_inactive:
            sig_count = db.session.query(yara_rule.Yara_rule).filter(yara_rule.Yara_rule.eventid >= self.range_min,
                                                                     yara_rule.Yara_rule.eventid <= self.range_max).count()
        else:
            sig_count = db.session.query(yara_rule.Yara_rule) \
                .filter(yara_rule.Yara_rule.eventid >= self.range_min, yara_rule.Yara_rule.eventid <= self.range_max) \
                .filter(yara_rule.Yara_rule.active > 0).count()

        return dict(
            id=self.id,
            category=self.category,
            range_min=self.range_min,
            range_max=self.range_max,
            current=self.current,
            sig_count=sig_count,
            include_in_release_notes=self.include_in_release_notes
        )

    @staticmethod
    def get_next_category_eventid(category=None, connection=None):
        from sqlalchemy import select, insert, update
        from sqlalchemy.exc import IntegrityError
        connection = connection or db.session.connection()
        table = CfgCategoryRangeMapping.__table__
        requested = category or CfgCategoryRangeMapping.DEFAULT_CATEGORY
        row = connection.execute(select(table).where(table.c.category == requested).with_for_update()).mappings().first()
        if row is None:
            requested = CfgCategoryRangeMapping.DEFAULT_CATEGORY
            row = connection.execute(select(table).where(table.c.category == requested).with_for_update()).mappings().first()
        if row is None:
            try:
                with connection.begin_nested():
                    connection.execute(insert(table).values(category=requested, range_min=10000,
                                                            range_max=20000, current=10000))
            except IntegrityError:
                pass
            row = connection.execute(select(table).where(table.c.category == requested).with_for_update()).mappings().one()
        eventid = max(row["current"] or row["range_min"], row["range_min"]) + 1
        rules = yara_rule.Yara_rule.__table__
        while connection.execute(select(rules.c.id).where(rules.c.eventid == eventid).limit(1)).first():
            eventid += 1
        if eventid > row["range_max"]:
            from flask import abort
            abort(409, description="Category EventID range is exhausted.")
        connection.execute(update(table).where(table.c.id == row["id"]).values(current=eventid))
        return eventid

    def __repr__(self):
        return '<CfgCategoryRangeMapping %r>' % self.id
