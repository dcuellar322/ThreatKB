from app import db
from app.models.yara_rule import Yara_rule, Yara_rule_history
from sqlalchemy import event


def test_detail_bounds_history_and_does_not_load_snapshot_blobs(authenticated):
    db.session.execute(
        Yara_rule.__table__.insert().values(
            name="history_heavy", eventid=10001, created_user_id=1, modified_user_id=1
        )
    )
    for revision in range(150):
        db.session.add(
            Yara_rule_history(
                yara_rule_id=1,
                revision=revision,
                user_id=1,
                rule_json='{"description":"' + "x" * 100000 + '"}',
            )
        )
    db.session.commit()
    statements = []

    def record(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", record)
    try:
        response = authenticated.get("/ThreatKB/yara_rules/1")
    finally:
        event.remove(db.engine, "before_cursor_execute", record)
    assert response.status_code == 200
    assert len(response.json["revisions"]) == 25
    history_selects = [
        sql
        for sql in statements
        if sql.lstrip().upper().startswith("SELECT")
        and "FROM yara_rules_history" in sql
    ]
    assert history_selects and all("_rule_json" not in sql for sql in history_selects)
    assert (
        authenticated.get("/ThreatKB/yara_rules/1?include_revisions=false").json[
            "revisions"
        ]
        == []
    )
