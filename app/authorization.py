"""One visibility policy for artifact and related-resource endpoints."""

from flask import abort
from flask_login import current_user
from sqlalchemy import or_, and_, exists, select
from app import db
from app.compat import strtobool
from app.models.cfg_settings import Cfg_settings


def artifact_models():
    from app.models.yara_rule import Yara_rule
    from app.models.c2ip import C2ip
    from app.models.c2dns import C2dns
    from app.models.tasks import Tasks

    return {1: Yara_rule, 2: C2dns, 3: C2ip, 4: Tasks}


def task_is_shared():
    value = Cfg_settings.get_setting("ENABLE_NON_ADMIN_TASK_VISIBILITY")
    return bool(value and strtobool(value))


def require_artifact(kind, identity, *, write=False):
    try:
        kind = int(kind)
        identity = int(identity)
    except TypeError, ValueError:
        abort(400, description="Choose a valid artifact.")
    model = artifact_models().get(kind)
    if model is None:
        abort(400, description="Choose a valid artifact type.")
    entity = db.get_or_404(model, identity)
    allowed = current_user.admin or entity.owner_user_id == current_user.id
    if not write and kind == 4:
        allowed |= task_is_shared() or entity.owner_user_id is None
    if not allowed:
        abort(403)
    return entity


def related_visibility(kind_column, identity_column):
    predicates = []
    for kind, model in artifact_models().items():
        owner = model.owner_user_id == current_user.id
        if kind == 4:
            owner = (
                True if task_is_shared() else or_(owner, model.owner_user_id.is_(None))
            )
        predicates.append(
            and_(
                kind_column == kind,
                exists(select(model.id).where(model.id == identity_column, owner)),
            )
        )
    return or_(*predicates)
