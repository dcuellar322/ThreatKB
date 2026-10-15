"""Load a consistent macro snapshot once per request or background task."""

from flask import g
from app import db
from app.models.macros import Macros
from app.models.cfg_settings import Cfg_settings


def macro_replacements():
    if not hasattr(g, "_macro_replacements"):
        template = Cfg_settings.get_setting("MACRO_TAG_TEMPLATE") or "[[%s]]"
        values = (
            db.session.query(Macros.tag, Macros.value)
            .filter(Macros.active.is_(True))
            .order_by(Macros.tag)
            .all()
        )
        g._macro_replacements = tuple(
            (template % tag, value or "") for tag, value in values
        )
    return g._macro_replacements


def expand(text):
    for token, value in macro_replacements():
        text = text.replace(token, value)
    return text
