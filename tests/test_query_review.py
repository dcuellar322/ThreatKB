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
