import json
import pytest
import yara
from app import app, db, bcrypt
from app.models.yara_rule import Yara_rule, Yara_rule_history
from app.models.cfg_states import Cfg_states
from app.models.users import KBUser
from app.models.files import Files
from app.signature_merge import merge_sources
from app.models.tasks import Tasks


def test_merge_preserves_overlapping_identifiers_literals_and_them_scope(authenticated):
    result = merge_sources(
        [
            'rule A {strings:$a="one" $ab="two" $x="$a literal" condition:$a and $ab and not $x}',
            'rule B {strings:$a="three" condition:any of them}',
        ],
        "Merged",
    )
    compiled = yara.compile(source=Yara_rule.to_yara_rule_string(result))
    assert compiled.match(data=b"one two")
    assert compiled.match(data=b"three")
    assert not compiled.match(data=b"one")
    assert "$a literal" in result["strings"]


def test_bulk_signature_edits_have_atomic_revision_history(authenticated):
    db.session.add(Cfg_states(state="Vetting"))
    db.session.add(Cfg_states(state="Retired"))
    db.session.commit()
    ids = []
    for name in ("BulkReviewA", "BulkReviewB"):
        r = authenticated.post(
            "/ThreatKB/yara_rules",
            json={"name": name, "state": "Vetting", "condition": "true"},
        )
        assert r.status_code == 201, r.json
        ids.append(r.json["id"])
    r = authenticated.put(
        "/ThreatKB/yara_rules/batch/edit",
        json={
            "batch": {
                "ids": ids,
                "state": "Retired",
                "description": "Reviewed together",
                "owner_user": None,
            }
        },
    )
    assert r.status_code == 200, r.json
    assert {row.revision for row in Yara_rule.query} == {2}
    assert {row.owner_user_id for row in Yara_rule.query} == {None}
    assert Yara_rule_history.query.count() == 4


def test_regular_analyst_cannot_read_or_delete_other_owners_data(
    authenticated, tmp_path
):
    db.session.add(
        KBUser(
            email="other@example.test",
            password=bcrypt.generate_password_hash("password").decode(),
            active=True,
            admin=False,
        )
    )
    db.session.flush()
    db.session.execute(
        Yara_rule.__table__.insert().values(
            name="PrivateReviewFixture",
            eventid=70001,
            condition="true",
            owner_user_id=1,
            created_user_id=1,
            modified_user_id=1,
        )
    )
    db.session.execute(
        Tasks.__table__.insert().values(
            title="Private task", owner_user_id=1, created_user_id=1, modified_user_id=1
        )
    )
    db.session.add(
        Files(
            filename="private.bin", sha1="a" * 40, entity_type=1, entity_id=1, user_id=1
        )
    )
    db.session.commit()
    c = app.test_client()
    assert (
        c.post(
            "/ThreatKB/login",
            json={"email": "other@example.test", "password": "password"},
        ).status_code
        == 200
    )
    search = c.get("/ThreatKB/search?all=Private").json
    assert search["signatures"] == [] and search["tasks"] == []
    assert c.get("/ThreatKB/files/1").status_code == 403
    assert c.get("/ThreatKB/files?entity_type=1&entity_id=1").status_code == 403
    assert (
        c.post(
            "/ThreatKB/bookmarks", json={"entity_type": 1, "entity_id": 1}
        ).status_code
        == 403
    )
    assert c.delete("/ThreatKB/tasks/1").status_code == 403
    assert c.put("/ThreatKB/yara_rules/delete_all_inactive", json={}).status_code == 403


def test_mitre_fields_survive_save_and_noop(authenticated):
    db.session.add(Cfg_states(state="Vetting"))
    db.session.commit()
    value = {
        "name": "MitreReviewFixture",
        "state": "Vetting",
        "condition": "true",
        "mitre_techniques": ["T1059"],
        "mitre_tactics": ["execution"],
        "mitre_sub_techniques": ["T1059.001"],
    }
    result = authenticated.post("/ThreatKB/yara_rules", json=value)
    assert result.status_code == 201, result.json
    assert result.json["mitre_techniques"] == ["T1059"]
    updated = authenticated.put(
        "/ThreatKB/yara_rules/" + str(result.json["id"]), json=value
    )
    assert updated.status_code == 200 and updated.json["revision"] == 1


def test_merge_into_updates_destination_and_missing_delete_is_404(authenticated):
    db.session.add(Cfg_states(state="Vetting", is_staging_state=1))
    db.session.add(Cfg_states(state="Merged"))
    db.session.commit()
    ids = []
    for name, text in [("MergeSource", "left"), ("MergeTarget", "right")]:
        result = authenticated.post(
            "/ThreatKB/yara_rules",
            json={
                "name": name,
                "state": "Vetting",
                "strings": f'$a="{text}"',
                "condition": "$a",
            },
        )
        assert result.status_code == 201, result.json
        ids.append(result.json["id"])
    identity = db.session.get(Yara_rule, ids[1]).uuid
    result = authenticated.post(
        "/ThreatKB/yara_rules/merge_signatures_by_id",
        json={"merge_from_id": ids[0], "merge_to_id": ids[1]},
    )
    assert result.status_code == 200, result.json
    target = db.session.get(Yara_rule, ids[1])
    assert target.uuid == identity and target.revision == 2
    source = authenticated.post(
        "/ThreatKB/yara_rules/copy", json={"copy": {"ids": [target.id]}}
    )
    assert source.status_code == 200, source.json
    compiled = yara.compile(source=source.json)
    assert compiled.match(data=b"left") and compiled.match(data=b"right")
    assert authenticated.delete("/ThreatKB/yara_rules/999").status_code == 404


def test_script_create_returns_new_script_and_quoted_arguments(authenticated):
    for name in ["first", "second"]:
        result = authenticated.post(
            "/ThreatKB/scripts",
            json={
                "name": name,
                "interpreter": "python3",
                "code": "import sys; print(sys.argv[1:])",
            },
        )
        assert result.status_code == 200, result.json
        assert result.json["name"] == name
    result = authenticated.post(
        "/ThreatKB/scripts/run/" + str(result.json["id"]),
        json={"arguments": '"two words" three'},
    )
    assert result.status_code == 200, result.json
    assert "['two words', 'three']" in result.json["stdout"]


def test_same_sample_with_two_filenames_remains_downloadable(authenticated, tmp_path):
    from app.models.cfg_settings import Cfg_settings
    from io import BytesIO

    db.session.add(Cfg_settings(key="FILE_STORE_PATH", value=str(tmp_path)))
    db.session.commit()
    for name in ["first.bin", "second.bin"]:
        response = authenticated.post(
            "/ThreatKB/file_upload",
            data={"file": (BytesIO(b"same sample bytes"), name)},
        )
        assert response.status_code == 200, response.json
    rows = Files.query.order_by(Files.id).all()
    assert len(rows) == 2
    for row in rows:
        response = authenticated.get("/ThreatKB/files/" + str(row.id))
        assert response.status_code == 200 and response.data == b"same sample bytes"


def test_release_build_batches_history_and_retains_signature_identity(authenticated):
    from app.models.cfg_category_range_mapping import CfgCategoryRangeMapping
    from sqlalchemy import event
    from datetime import datetime

    db.session.add_all(
        [
            Cfg_states(state="Released", is_release_state=1),
            Cfg_states(state="Vetting", is_staging_state=1),
            Cfg_states(state="Retired", is_retired_state=1),
            CfgCategoryRangeMapping(
                category="Uncategorized",
                range_min=10000,
                range_max=20000,
                current=10000,
            ),
        ]
    )
    db.session.flush()
    db.session.execute(
        Yara_rule.__table__.insert(),
        [
            {
                "name": f"ReleaseReview{i}",
                "eventid": 10001 + i,
                "state": "Released",
                "category": "Uncategorized",
                "condition": "true",
                "created_user_id": 1,
                "modified_user_id": 1,
                "owner_user_id": 1,
                "creation_date": datetime.now(),
                "last_revision_date": datetime.now(),
                "revision": 1,
            }
            for i in range(25)
        ],
    )
    db.session.commit()
    queries = []

    def capture(conn, cursor, statement, params, context, many):
        queries.append(statement)

    event.listen(db.engine, "before_cursor_execute", capture)
    try:
        response = authenticated.post(
            "/ThreatKB/releases?short=true",
            json={"name": "Review release", "is_test_release": False},
        )
        assert response.status_code == 200, response.json
        assert response.json["num_signatures"] == 25
        assert len([s for s in queries if s.lstrip().startswith("SELECT")]) < 25, len(
            queries
        )
    finally:
        event.remove(db.engine, "before_cursor_execute", capture)
    for snapshot in Yara_rule_history.query:
        assert (
            snapshot.to_dict()["rule_json"]["uuid"]
            == db.session.get(Yara_rule, snapshot.yara_rule_id).uuid
        )


def test_revoked_api_key_cannot_be_reactivated(authenticated):
    key = authenticated.post("/ThreatKB/access_keys", json={}).json
    assert (
        authenticated.put(
            "/ThreatKB/access_keys/" + str(key["id"]), json={"status": "deleted"}
        ).status_code
        == 200
    )
    assert (
        authenticated.put(
            "/ThreatKB/access_keys/" + str(key["id"]), json={"status": "active"}
        ).status_code
        == 409
    )


def test_purge_removes_test_children_and_schedules(authenticated):
    from datetime import datetime, timedelta
    from app.models.yara_rule import (
        Yara_testing_history,
        Yara_testing_history_files_matches,
    )
    from app.models.scheduled_confidence import ScheduledConfidence

    db.session.add(Cfg_states(state="Vetting"))
    db.session.commit()
    response = authenticated.post(
        "/ThreatKB/yara_rules",
        json={"name": "PurgeFixture", "state": "Vetting", "condition": "true"},
    )
    identity = response.json["id"]
    test = Yara_testing_history(
        test_type="POSITIVE",
        yara_rule_id=identity,
        revision=1,
        start_time=datetime.now(),
        status="COMPLETE",
        total_files=1,
        files_tested=1,
        files_matched=1,
        avg_millis_per_file=0,
        user_id=1,
    )
    db.session.add(test)
    db.session.flush()
    db.session.add(
        Yara_testing_history_files_matches(
            history_id=test.id, run_time=0, path="sample.bin", matched=True
        )
    )
    db.session.add(
        ScheduledConfidence(
            rule_id=identity,
            confidence=90,
            due_at=datetime.now() + timedelta(days=1),
            created_user_id=1,
        )
    )
    db.session.commit()
    assert (
        authenticated.delete("/ThreatKB/yara_rules/" + str(identity)).status_code == 204
    )
    response = authenticated.put("/ThreatKB/yara_rules/delete_all_inactive", json={})
    assert response.status_code == 200, response.json
    assert (
        Yara_rule.query.count()
        == Yara_testing_history.query.count()
        == Yara_testing_history_files_matches.query.count()
        == ScheduledConfidence.query.count()
        == 0
    )


def test_used_definitions_cannot_orphan_release_content(authenticated):
    from app.models.cfg_category_range_mapping import CfgCategoryRangeMapping

    category = CfgCategoryRangeMapping(
        category="UsedCategory", range_min=20000, range_max=29999, current=20000
    )
    state = Cfg_states(state="HistoricRelease", is_release_state=1)
    db.session.add_all(
        [category, state, Cfg_states(state="Vetting", is_staging_state=1)]
    )
    db.session.commit()
    category_id, state_id = category.id, state.id
    response = authenticated.post(
        "/ThreatKB/yara_rules",
        json={
            "name": "DefinitionFixture",
            "category": "UsedCategory",
            "state": "Vetting",
            "condition": "true",
        },
    )
    assert response.status_code == 201, response.json
    assert (
        authenticated.put(
            "/ThreatKB/cfg_category_range_mapping/" + str(category_id),
            json={
                "category": "Renamed",
                "range_min": 20000,
                "range_max": 29999,
                "include_in_release_notes": True,
            },
        ).status_code
        == 409
    )
    assert (
        authenticated.delete(
            "/ThreatKB/cfg_category_range_mapping/" + str(category_id)
        ).status_code
        == 409
    )
    history = Yara_rule_history.query.first()
    history.state = "HistoricRelease"
    db.session.commit()
    assert (
        authenticated.delete("/ThreatKB/cfg_states/" + str(state_id)).status_code == 409
    )


def test_task_tags_persist_through_create_edit_and_bulk(authenticated):
    db.session.add(Cfg_states(state="Vetting"))
    db.session.commit()
    payload = dict(
        title="Tagged task",
        state="Vetting",
        description="Initial",
        final_artifact="",
        tags=["first", "second"],
    )
    response = authenticated.post("/ThreatKB/tasks", json=payload)
    assert response.status_code == 201
    identity = response.json["id"]
    assert response.json["tags"] == ["first", "second"]
    payload["tags"] = [{"text": "third"}]
    assert authenticated.put(f"/ThreatKB/tasks/{identity}", json=payload).json[
        "tags"
    ] == ["third"]
    assert (
        authenticated.put(
            "/ThreatKB/tasks/batch/edit",
            json={"batch": {"ids": [identity], "tags": ["bulk"]}},
        ).status_code
        == 200
    )
    assert authenticated.get(f"/ThreatKB/tasks/{identity}").json["tags"] == [
        "bulk",
        "third",
    ]
    listed = authenticated.get(
        "/ThreatKB/tasks", query_string={"searches": json.dumps({"tags": "bulk"})}
    ).json
    assert listed["total_count"] == 1 and listed["data"][0]["tags"] == ["bulk", "third"]
    payload["tags"] = []
    assert (
        authenticated.put(f"/ThreatKB/tasks/{identity}", json=payload).json["tags"]
        == []
    )
