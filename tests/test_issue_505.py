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


def test_bulk_category_change_preserves_existing_identity(authenticated):
    from app.models.cfg_states import Cfg_states
    from app.models.yara_rule import Yara_rule

    db.session.add(Cfg_states(state="Vetting"))
    db.session.add(
        CfgCategoryRangeMapping(
            category="Other", range_min=30000, range_max=40000, current=30000
        )
    )
    db.session.commit()
    created = authenticated.post(
        "/ThreatKB/yara_rules",
        json={
            "name": "BulkIdentity",
            "strings": "",
            "condition": "true",
            "state": "Vetting",
            "category": "Uncategorized",
        },
    )
    assert created.status_code == 201, created.json
    original = created.json
    updated = authenticated.put(
        "/ThreatKB/yara_rules/batch/edit",
        json={"batch": {"ids": [original["id"]], "category": {"category": "Other"}}},
    )
    assert updated.status_code == 200, updated.json
    rule = db.session.get(Yara_rule, original["id"])
    db.session.refresh(rule)
    assert (
        rule.eventid == original["eventid"]
        and rule.uuid == original["uuid"]
        and rule.category == "Other"
    )
