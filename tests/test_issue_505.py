import pytest
from sqlalchemy.exc import IntegrityError
from app import db
from app.models.yara_rule import Yara_rule
from app.models.cfg_category_range_mapping import CfgCategoryRangeMapping


def test_eventid_allocation_and_database_uniqueness(authenticated):
    connection = db.session.connection()
    first = CfgCategoryRangeMapping.get_next_category_eventid(connection=connection)
    second = CfgCategoryRangeMapping.get_next_category_eventid(connection=connection)
    assert second == first + 1
    row = dict(name="first", eventid=first, created_user_id=1, modified_user_id=1)
    db.session.execute(Yara_rule.__table__.insert().values(**row))
    with pytest.raises(IntegrityError):
        with db.session.begin_nested():
            db.session.execute(
                Yara_rule.__table__.insert().values(**{**row, "name": "second"})
            )
