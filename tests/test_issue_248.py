from datetime import datetime
from app import db
from app.models.activity_log import ActivityLog
from app.models.bookmarks import Bookmarks
from app.models.users import KBUser


def test_bookmarked_activity_notifications_have_clear_cursor(authenticated):
    db.session.add(KBUser(email='reviewer@example.test', password='unused', active=True))
    db.session.flush()
    db.session.add(Bookmarks(entity_type=1, entity_id=77, user_id=1))
    db.session.execute(ActivityLog.__table__.insert().values(activity_type='COMMENTS', activity_text='Peer review',
        activity_date=datetime.now(), entity_type=1, entity_id=77, user_id=2))
    db.session.commit()
    response = authenticated.get('/ThreatKB/notifications')
    assert response.json['unread_count'] == 1
    assert response.json['data'][0]['activity_text'] == 'Peer review'
    assert authenticated.post('/ThreatKB/notifications/clear').json['unread_count'] == 0
    assert authenticated.get('/ThreatKB/notifications').json['unread_count'] == 0
