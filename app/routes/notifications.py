from flask import jsonify
from flask_login import login_required, current_user
from sqlalchemy import exists, and_, or_
from app import app, db
from app.models.activity_log import ActivityLog
from app.models.bookmarks import Bookmarks
from app.models.cfg_settings import Cfg_settings
from app.models.yara_rule import Yara_rule
from app.models.c2ip import C2ip
from app.models.c2dns import C2dns
from app.models.tasks import Tasks


@app.get('/ThreatKB/notifications')
@login_required
def artifact_notifications():
    cursor = db.session.get(Cfg_settings, f'NOTIFICATION_CURSOR:{current_user.id}')
    after = int(cursor.value) if cursor else 0
    bookmarked = exists().where(and_(Bookmarks.user_id == current_user.id,
        Bookmarks.entity_type == ActivityLog.entity_type, Bookmarks.entity_id == ActivityLog.entity_id))
    owned = []
    for kind, model in ((1, Yara_rule), (2, C2dns), (3, C2ip), (4, Tasks)):
        owned.append(and_(ActivityLog.entity_type == kind, exists().where(and_(
            model.id == ActivityLog.entity_id, model.owner_user_id == current_user.id))))
    query = ActivityLog.query.filter(ActivityLog.id > after, or_(bookmarked, *owned),
        or_(ActivityLog.user_id != current_user.id, ActivityLog.user_id.is_(None)))
    return jsonify(unread_count=query.count(), after_id=after,
                   data=[item.to_dict() for item in query.order_by(ActivityLog.id.desc()).limit(100)])


@app.post('/ThreatKB/notifications/clear')
@login_required
def clear_artifact_notifications():
    last_id = db.session.query(db.func.max(ActivityLog.id)).scalar() or 0
    key = f'NOTIFICATION_CURSOR:{current_user.id}'
    cursor = db.session.get(Cfg_settings, key)
    if cursor is None:
        cursor = Cfg_settings(key=key, public=False, description='Last cleared activity notification')
        db.session.add(cursor)
    cursor.value = str(last_id)
    db.session.commit()
    return jsonify(after_id=last_id, unread_count=0)
