from app import db, cache


class Cfg_settings(db.Model):
    __tablename__ = "cfg_settings"

    key = db.Column(db.String(512), index=True, primary_key=True)
    date_created = db.Column(
        db.DateTime(timezone=True), default=db.func.current_timestamp()
    )
    date_modified = db.Column(
        db.DateTime(timezone=True),
        default=db.func.current_timestamp(),
        onupdate=db.func.current_timestamp(),
    )
    public = db.Column(db.Boolean, index=True, default=True)
    value = db.Column(db.TEXT())
    description = db.Column(db.String(512))

    def to_dict(self):
        return dict(
            date_created=self.date_created.isoformat(),
            date_modified=self.date_modified.isoformat(),
            key=self.key,
            public=self.public,
            value=self.value,
            description=self.description,
        )

    def __repr__(self):
        return "<Cfg_settings %s>" % (self.key)

    @staticmethod
    @cache.memoize(timeout=60)
    def get_private_setting(key):
        try:
            setting = (
                db.session.query(Cfg_settings)
                .filter(Cfg_settings.public == False)
                .filter(Cfg_settings.key == key)
                .first()
            )
            return setting.value if setting else None
        except:
            return None

    @staticmethod
    @cache.memoize(timeout=60)
    def get_setting(key):
        try:
            setting = (
                db.session.query(Cfg_settings).filter(Cfg_settings.key == key).first()
            )
            return setting.value if setting else None
        except:
            return None

    @staticmethod
    @cache.memoize(timeout=60)
    def get_settings(key_like):
        try:
            return (
                db.session.query(Cfg_settings)
                .filter(Cfg_settings.key.like(key_like))
                .all()
            )
        except Exception as e:
            return None


from sqlalchemy import event


@event.listens_for(Cfg_settings, "after_insert")
@event.listens_for(Cfg_settings, "after_update")
@event.listens_for(Cfg_settings, "after_delete")
def invalidate_settings_cache(mapper, connection, target):
    if target.key == "MACRO_TAG_TEMPLATE":
        from flask import g, has_app_context

        if has_app_context():
            g.pop("_macro_replacements", None)
    cache.delete_memoized(Cfg_settings.get_setting, target.key)
    cache.delete_memoized(Cfg_settings.get_private_setting, target.key)
    cache.delete_memoized(Cfg_settings.get_settings)
