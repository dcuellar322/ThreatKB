import json
from app import db
from app.models.yara_rule import Yara_rule
from app.models.tags import Tags
from app.models.tags_mapping import Tags_mapping
from app.models.comments import Comments
from app.models.metadata import Metadata, MetadataMapping
from sqlalchemy import event


def fixtures():
    db.session.execute(
        Yara_rule.__table__.insert(),
        [
            dict(
                name=f"Query_{i:03}",
                eventid=60000 + i,
                uuid=f"cccccccc-cccc-4ccc-8ccc-{i:012}",
                condition="true",
                state="Vetting",
                category="Uncategorized",
                created_user_id=1,
                modified_user_id=1,
                owner_user_id=1,
            )
            for i in range(60)
        ],
    )
    db.session.add_all([Tags(text="blocked"), Tags(text="other")])
    db.session.flush()
    db.session.add_all(
        [
            Tags_mapping(source_table="yara_rules", source_id=1, tag_id=1),
            Tags_mapping(source_table="yara_rules", source_id=1, tag_id=2),
            Tags_mapping(source_table="yara_rules", source_id=2, tag_id=2),
        ]
    )
    db.session.add(
        Comments(entity_type=1, entity_id=1, comment="Review needle", user_id=1)
    )
    for key, value in [("FieldA", "one"), ("FieldB", "two")]:
        field = Metadata(key=key, type_="string", artifact_type=1, created_user_id=1)
        db.session.add(field)
        db.session.flush()
        db.session.add(
            MetadataMapping(
                metadata_id=field.id, artifact_id=1, value=value, created_user_id=1
            )
        )
    db.session.commit()


def test_filters_count_distinct_artifacts_and_negation(authenticated):
    fixtures()

    def get(filters):
        return authenticated.get(
            "/ThreatKB/yara_rules",
            query_string={"searches": json.dumps(filters), "page_size": 100},
        ).json

    assert get({"FieldA": "one", "FieldB": "two"})["total_count"] == 1
    assert [r["id"] for r in get({"comments": "needle"})["data"]] == [1]
    assert 1 not in [r["id"] for r in get({"tags": "!blocked"})["data"]]
    assert get({"tags": "~"})["total_count"] == 58
    assert get({"comments": "~"})["total_count"] == 59
    assert get({"FieldA": "~"})["total_count"] == 59


def test_list_queries_are_bounded_by_page_not_row_count(authenticated):
    fixtures()
    statements = []

    def capture(*args):
        statements.append(args[2])

    event.listen(db.engine, "before_cursor_execute", capture)
    try:
        for size in (5, 50):
            statements.clear()
            response = authenticated.get(
                "/ThreatKB/yara_rules",
                query_string={"page_size": size, "include_comments": "true"},
            )
            assert response.status_code == 200
            assert len(response.json["data"]) == size
            assert len(statements) <= 12, (size, len(statements))
    finally:
        event.remove(db.engine, "before_cursor_execute", capture)


def test_pagination_is_stable_and_invalid_inputs_are_rejected(authenticated):
    fixtures()
    first = authenticated.get(
        "/ThreatKB/yara_rules?page_size=25&sort_by=state&sort_dir=ASC"
    ).json
    second = authenticated.get(
        "/ThreatKB/yara_rules?page_size=25&page_number=1&sort_by=state&sort_dir=ASC"
    ).json
    assert not {r["id"] for r in first["data"]} & {r["id"] for r in second["data"]}
    for query in (
        "page_size=-1",
        "page_size=100000",
        "page_number=-1",
        "searches=[]",
        "searches=broken",
    ):
        assert authenticated.get("/ThreatKB/yara_rules?" + query).status_code == 400


def test_text_search_combines_with_structured_filters(authenticated):
    fixtures()
    response = authenticated.get(
        "/ThreatKB/yara_rules",
        query_string={
            "q": "Fixture",
            "searches": json.dumps({"name": {"op": "eq", "value": "does_not_exist"}}),
        },
    )
    assert response.status_code == 200 and response.json["total_count"] == 0


def test_bulk_compilation_loads_macros_once_and_reuses_compiled_rules(authenticated):
    from app.detection import compile_active_rules
    from app.models.macros import Macros
    from app.models.cfg_settings import Cfg_settings
    from flask import g

    fixtures()
    db.session.add_all(
        [
            Cfg_settings(key="MACRO_TAG_TEMPLATE", value="[[%s]]"),
            Macros(
                tag="macro_test",
                value="true",
                active=True,
                created_user_id=1,
                modified_user_id=1,
            ),
        ]
    )
    db.session.commit()
    g.pop("_macro_replacements", None)
    statements = []

    def capture(conn, cursor, statement, params, context, many):
        statements.append(statement)

    event.listen(db.engine, "before_cursor_execute", capture)
    try:
        first = compile_active_rules()
        second = compile_active_rules()
        assert first is second
        assert len([s for s in statements if "FROM macros" in s]) == 1
        assert len(statements) < 7, len(statements)
    finally:
        event.remove(db.engine, "before_cursor_execute", capture)


def test_test_history_sorting_rejects_sql_and_checks_access(authenticated):
    assert (
        authenticated.get(
            "/ThreatKB/tests?sort_by=id%3BDROP%20TABLE%20kb_users"
        ).status_code
        == 400
    )
    assert authenticated.get("/ThreatKB/tests?page_size=100000").status_code == 400
    assert authenticated.get("/ThreatKB/tests/9999").status_code == 404


def test_test_history_sorts_by_signature_name_with_stable_page_boundaries(
    authenticated,
):
    from datetime import datetime
    from app.models.yara_rule import Yara_testing_history

    fixtures()
    for identity in (2, 1, 2):
        db.session.add(
            Yara_testing_history(
                yara_rule_id=identity,
                revision=1,
                test_type="POSITIVE",
                start_time=datetime.now(),
                status="COMPLETE",
                total_files=1,
                files_tested=1,
                files_matched=0,
                avg_millis_per_file=0,
                user_id=1,
            )
        )
    db.session.commit()
    response = authenticated.get(
        "/ThreatKB/tests?sort_by=yara_rule_name&sort_dir=ASC&page_size=2"
    )
    assert response.status_code == 200
    assert [row["yara_rule_name"] for row in response.json["data"]] == [
        "Query_000",
        "Query_001",
    ]
    assert [row["id"] for row in response.json["data"]] == [2, 1]
    second = authenticated.get(
        "/ThreatKB/tests?sort_by=yara_rule_name&sort_dir=ASC&page_size=2&page_number=1"
    )
    assert [row["id"] for row in second.json["data"]] == [3]
    reverse = authenticated.get("/ThreatKB/tests?sort_by=yara_rule_name&sort_dir=DESC")
    assert [row["id"] for row in reverse.json["data"]] == [3, 1, 2]


def test_overview_restores_scoped_ownership_and_category_aggregates(authenticated):
    from app.models.users import KBUser

    fixtures()
    other = KBUser(
        email="other-owner@example.test", password="unused", active=True, admin=False
    )
    db.session.add(other)
    db.session.flush()
    db.session.execute(
        Yara_rule.__table__.update()
        .where(Yara_rule.id == 1)
        .values(owner_user_id=other.id)
    )
    db.session.commit()
    summary = authenticated.get("/ThreatKB/dashboard").json
    assert summary["counts"]["signatures"] == 60
    assert summary["categories"] == [{"category": "Uncategorized", "count": 60}]
    assert {
        owner["email"]: owner["counts"]["signatures"] for owner in summary["ownership"]
    } == {"analyst@example.test": 59, "other-owner@example.test": 1}
    db.session.get(KBUser, 1).admin = False
    db.session.commit()
    scoped = authenticated.get("/ThreatKB/dashboard").json
    assert scoped["counts"]["signatures"] == 59
    assert scoped["ownership"] == [
        {
            "email": "analyst@example.test",
            "counts": {"signatures": 59, "ips": 0, "domains": 0, "tasks": 0},
        }
    ]
    assert scoped["categories"] == [{"category": "Uncategorized", "count": 59}]
    assert scoped["releases"] == []



def test_empty_text_and_date_only_comparisons(authenticated):
    fixtures()
    for identity, description in [(1, ""), (2, "Present")]:
        db.session.execute(
            Yara_rule.__table__.update()
            .where(Yara_rule.id == identity)
            .values(description=description)
        )
    field = Metadata(key="DueAt", type_="date", artifact_type=1, created_user_id=1)
    db.session.add(field)
    db.session.flush()
    for identity, date in [(1, "2000-01-01"), (2, "2999-01-01")]:
        db.session.add(MetadataMapping(
            metadata_id=field.id, artifact_id=identity, value=date, created_user_id=1,
        ))
    db.session.commit()

    def get(field, operation):
        return authenticated.get(
            "/ThreatKB/yara_rules",
            query_string={
                "searches": json.dumps({field: {"op": operation}}),
                "page_size": 100,
            },
        )

    response = get("description", "empty")
    assert response.status_code == 200
    assert response.json["total_count"] == 59
    assert {row["id"] for row in response.json["data"]} == set(range(1, 61)) - {2}
    for field in ("name", "tags", "owner_user.email", "FieldA"):
        assert get(field, "before_now").status_code == 400
    assert [row["id"] for row in get("DueAt", "before_now").json["data"]] == [1]
    assert [row["id"] for row in get("DueAt", "after_now").json["data"]] == [2]
