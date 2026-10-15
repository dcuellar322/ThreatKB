from datetime import datetime, timezone, timedelta
from hashlib import sha256
from uuid import uuid4
import yaml
import pytest
from threatkb_content.engine import Repository, ContentError, regex_chunks


def content(tmp_path):
    root = tmp_path / "content"
    (root / "rules").mkdir(parents=True)
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    sample = b"SYNTHETIC_CONTENT_FIXTURE"
    digest = sha256(sample).hexdigest()
    (corpus / digest).write_bytes(sample)
    rule = {
        "id": str(uuid4()),
        "name": "Fixture",
        "category": "SC",
        "status": "released",
        "strings": '$a = "SYNTHETIC_CONTENT_FIXTURE"',
        "condition": "$a",
        "groups": ["default"],
        "references": {"public": {"samples": [digest]}},
        "testing_strategy": ["match_all_referenced_samples"],
    }
    (root / "rules" / "fixture.yaml").write_text(yaml.safe_dump(rule))
    (root / "policies.yaml").write_text(
        yaml.safe_dump(
            {
                "groups": {
                    "default": {"categories": ["SC"]},
                    "other": {"categories": ["MC"]},
                },
                "promotion_wait_minutes": 30,
                "required_consumers": ["local"],
            }
        )
    )
    return root, corpus


def test_yaml_uuid_category_macro_and_group_isolation(tmp_path):
    root, corpus = content(tmp_path)
    repo = Repository(root, corpus)
    assert repo.check()["positive_samples"] == 1
    assert "rule SC_Fixture" in repo.materialize(repo.selected())
    assert repo.selected("other") == []
    chunks = regex_chunks(["value" + str(i) for i in range(300)])
    assert len(chunks) > 1 and all(len(chunk.encode()) <= 512 for chunk in chunks)
    with pytest.raises(ContentError):
        repo.render("{{ unknown_macro }}")


def test_testing_window_telemetry_alarms_and_independent_review(tmp_path):
    root, corpus = content(tmp_path)
    repo = Repository(root, corpus)
    manifest = repo.build(tmp_path / "builds")
    channels = tmp_path / "channels"
    with pytest.raises(ContentError):
        repo.publish_testing(manifest, channels)
    (root / "review.yaml").write_text(
        yaml.safe_dump(
            {
                "author": "analyst-a",
                "reviewer": "analyst-b",
                "source_digest": repo.digest(),
            }
        )
    )
    start = datetime.now(timezone.utc)
    repo.publish_testing(manifest, channels, start)
    with pytest.raises(ContentError):
        repo.promote(channels, "sigpack", "default", start + timedelta(minutes=10))
    report = {
        "window_start": start.isoformat(),
        "window_end": (start + timedelta(minutes=31)).isoformat(),
        "detections": 0,
        "errors": 1,
    }
    repo.telemetry(
        channels,
        "sigpack",
        "default",
        manifest["id"],
        "local",
        report,
        start + timedelta(minutes=31),
    )
    with pytest.raises(ContentError):
        repo.promote(channels, "sigpack", "default", start + timedelta(minutes=31))
    report["errors"] = 0
    repo.telemetry(
        channels,
        "sigpack",
        "default",
        manifest["id"],
        "local",
        report,
        start + timedelta(minutes=31),
    )
    assert (
        repo.promote(channels, "sigpack", "default", start + timedelta(minutes=31))[
            "status"
        ]
        == "production"
    )


def test_promotion_is_idempotent_and_future_telemetry_rejected(tmp_path):
    root, corpus = content(tmp_path)
    repo = Repository(root, corpus)
    manifest = repo.build(tmp_path / "builds")
    (root / "review.yaml").write_text(
        yaml.safe_dump({"author": "a", "reviewer": "b", "source_digest": repo.digest()})
    )
    channels = tmp_path / "channels"
    start = datetime.now(timezone.utc) - timedelta(minutes=31)
    repo.publish_testing(manifest, channels, start)
    report = {
        "window_start": start.isoformat(),
        "window_end": (start + timedelta(minutes=31)).isoformat(),
        "detections": 0,
        "errors": 0,
    }
    with pytest.raises(ContentError):
        repo.telemetry(
            channels, "sigpack", "default", manifest["id"], "local", report, start
        )
    repo.telemetry(channels, "sigpack", "default", manifest["id"], "local", report)
    first = repo.promote(channels, "sigpack", "default")
    assert (
        repo.promote(
            channels,
            "sigpack",
            "default",
            datetime.now(timezone.utc) + timedelta(hours=2),
        )
        == first
    )


def test_feedpack_is_independent_of_invalid_signature_yaml(tmp_path):
    root, corpus = content(tmp_path)
    (root / "rules" / "fixture.yaml").write_text("invalid: rule\n")
    (root / "indicators.yaml").write_text(
        yaml.safe_dump([{"value": "192.0.2.42", "type": "ip", "groups": ["default"]}])
    )
    manifest = Repository(root, corpus, load_rules=False).build(
        tmp_path / "builds", kind="feedpack"
    )
    assert manifest["valid"] and manifest["indicators"] == 1


def test_promotion_keeps_reviewed_policy_and_exposes_persistent_alarm(tmp_path):
    root, corpus = content(tmp_path)
    repo = Repository(root, corpus)
    manifest = repo.build(tmp_path / "builds")
    review = {"author": "a", "reviewer": "b", "source_digest": repo.digest()}
    channels = tmp_path / "channels"
    start = datetime.now(timezone.utc) - timedelta(minutes=31)
    repo.publish_testing(manifest, channels, start, review=review)
    # A later mutable configuration cannot weaken the policy for this release.
    repo.policy["required_consumers"] = []
    repo.policy["max_detection_rate"] = 999999
    with pytest.raises(ContentError, match="Missing telemetry"):
        repo.promote(channels, "sigpack", "default")
    report = {
        "window_start": start.isoformat(),
        "window_end": datetime.now(timezone.utc).isoformat(),
        "detections": 0,
        "errors": 1,
    }
    repo.telemetry(channels, "sigpack", "default", manifest["id"], "local", report)
    with pytest.raises(ContentError, match="alarm"):
        repo.promote(channels, "sigpack", "default")
    import json

    state = json.loads((channels / "sigpack/default/testing.json").read_text())
    assert state["promotion_block"]["alarm"]
    since = state["promotion_block"]["since"]
    with pytest.raises(ContentError):
        repo.promote(channels, "sigpack", "default")
    assert (
        json.loads((channels / "sigpack/default/testing.json").read_text())[
            "promotion_block"
        ]["since"]
        == since
    )
