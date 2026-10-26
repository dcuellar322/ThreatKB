from datetime import datetime, timedelta, timezone
import json
import yaml
import pytest
from click.testing import CliRunner
from threatkb_content.__main__ import cli
from threatkb_content.engine import Repository
from threatkb_content.intelligence import evaluate, normalize

NOW = datetime(2026, 10, 15, 12, tzinfo=timezone.utc)
SOURCES = {"feed": {"confidence": 85, "severity": 60, "groups": ["default"]}}
POLICY = {"min_confidence": 70, "allow_non_global_ips": True}


def observation(**extra):
    return {
        "source": "feed",
        "type": "domain",
        "value": "C2.EXAMPLE.TEST.",
        "observed_at": (NOW - timedelta(hours=1)).isoformat(),
        **extra,
    }


def test_normalization_quarantine_deduplication_and_source_trust_cap():
    report = evaluate(
        [
            observation(),
            observation(),
            observation(value="bad/host"),
            observation(type="ip", value="2001:0db8::1", confidence=100),
        ],
        SOURCES,
        {**POLICY, "require_review": False},
        now=NOW,
    )
    assert report["summary"] == {
        "released": 2,
        "held": 0,
        "retired": 0,
        "invalid": 1,
        "observations": 3,
    }
    assert report["released"][0]["value"] == "c2.example.test"
    assert report["released"][1]["value"] == "2001:db8::1"
    assert report["released"][1]["confidence"] == 85
    with pytest.raises(ValueError):
        normalize("domain", "192.0.2.1")
    assert normalize("domain", "BÜCHER.example") == "xn--bcher-kva.example"


def test_independent_review_is_bound_to_observation_digest():
    raw = [observation()]
    held = evaluate(raw, SOURCES, POLICY, now=NOW)["held"][0]
    decision = {
        "decision": "approved",
        "record_digest": held["record_digest"],
        "author": "a",
        "reviewer": "b",
    }
    assert evaluate(raw, SOURCES, POLICY, decisions={held["id"]: decision}, now=NOW)[
        "released"
    ]
    assert evaluate(
        raw,
        SOURCES,
        POLICY,
        decisions={held["id"]: {**decision, "reviewer": "a"}},
        now=NOW,
    )["held"]
    changed = [observation(confidence=71)]
    result = evaluate(
        changed, SOURCES, POLICY, decisions={held["id"]: decision}, now=NOW
    )
    assert result["held"][0]["id"] == held["id"]
    assert result["held"][0]["record_digest"] != held["record_digest"]


def test_expiration_stale_future_allowlist_and_reserved_ip_policy():
    raw = [
        observation(
            value="expired.example.test",
            expires_at=(NOW - timedelta(minutes=1)).isoformat(),
        ),
        observation(
            value="old.example.test",
            observed_at=(NOW - timedelta(days=100)).isoformat(),
        ),
        observation(
            value="future.example.test",
            observed_at=(NOW + timedelta(seconds=1)).isoformat(),
        ),
        observation(type="ip", value="127.0.0.1"),
        observation(value="allowed.example.test"),
        observation(value="notallowed.example.test"),
    ]
    report = evaluate(
        raw,
        SOURCES,
        {
            "require_review": False,
            "allowlist": [{"domain_suffix": "allowed.example.test"}],
        },
        now=NOW,
    )
    assert report["summary"]["retired"] == 1
    assert report["summary"]["invalid"] == 1
    assert report["summary"]["held"] == 3
    assert report["released"][0]["value"] == "notallowed.example.test"


def test_enrichment_uses_network_and_domain_boundaries_without_overwriting_scores():
    enrichment = [
        {
            "network": "198.51.100.0/24",
            "provider": "fixture",
            "asn": 64500,
            "confidence": 100,
        },
        {"domain_suffix": "example.test", "provider": "fixture", "sector": "test"},
    ]
    report = evaluate(
        [observation(type="ip", value="198.51.100.42"), observation()],
        SOURCES,
        {**POLICY, "require_review": False},
        enrichment=enrichment,
        now=NOW,
    )
    assert len(report["released"]) == 2
    assert all(
        row["confidence"] == 85 and len(row["enrichment"]) == 1
        for row in report["released"]
    )
    assert report["released"][1]["enrichment"][0]["asn"] == 64500


def test_latest_observation_supersedes_retirement_and_invalid_source_is_quarantined():
    report = evaluate(
        [
            observation(
                status="retired", observed_at=(NOW - timedelta(days=1)).isoformat()
            ),
            observation(),
            observation(source="spoofed"),
            observation(confidence=True),
        ],
        SOURCES,
        {**POLICY, "require_review": False},
        now=NOW,
    )
    assert report["summary"]["released"] == 1
    assert report["summary"]["invalid"] == 2


def test_cli_quarantines_bad_rows_and_exports_only_approved_data_to_feedpack(tmp_path):
    raw = tmp_path / "raw.csv"
    raw.write_text(
        "type,value,observed_at,source\ndomain,c2.example.test,2026-10-01T00:00:00Z,spoofed\ndomain,bad/host,2026-10-01T00:00:00Z,spoofed\n"
    )
    sources = tmp_path / "sources.yaml"
    sources.write_text(yaml.safe_dump(SOURCES))
    policy = tmp_path / "policy.yaml"
    policy.write_text(yaml.safe_dump({"require_review": False}))
    output = tmp_path / "assessment"
    result = CliRunner().invoke(
        cli,
        [
            "evaluate-iocs",
            "--input",
            str(raw),
            "--source",
            "feed",
            "--sources",
            str(sources),
            "--policy",
            str(policy),
            "--output",
            str(output),
        ],
    )
    assert result.exit_code != 0 and "quarantined" in result.output
    report = json.loads((output / "assessment.json").read_text())
    assert report["summary"]["invalid"] == 1
    assert report["released"][0]["provenance"][0]["source"] == "feed"
    manifest = Repository(output, load_rules=False).build(
        tmp_path / "builds", kind="feedpack"
    )
    assert manifest["indicators"] == 1


def test_cross_group_source_confidence_cannot_leak_and_conflicts_fail_closed():
    sources = {**SOURCES, "low": {"confidence": 10, "groups": ["other"]}}
    report = evaluate(
        [observation(), observation(source="low", groups=["other"], confidence=100)],
        sources,
        {**POLICY, "require_review": False},
        now=NOW,
    )
    assert report["released"][0]["groups"] == ["default"]
    conflicts = [observation(confidence=80), observation(confidence=81)]
    first = evaluate(conflicts, SOURCES, {**POLICY, "require_review": False}, now=NOW)
    second = evaluate(
        list(reversed(conflicts)), SOURCES, {**POLICY, "require_review": False}, now=NOW
    )
    assert first["held"] == second["held"]
    assert "conflicting" in first["held"][0]["reasons"][0]
    with pytest.raises(ValueError):
        normalize("domain", "example.test..")


def test_repository_pipeline_binds_csv_inputs_and_keeps_codepack_independent(tmp_path):
    import shutil
    from pathlib import Path

    root = tmp_path / "content"
    shutil.copytree(Path(__file__).resolve().parents[1] / "detections", root)
    repo = Repository(root, load_rules=False)
    initial = repo.digest()
    report = repo.build(tmp_path / "builds", kind="feedpack")
    assert report["indicators"] == 2
    (root / "intelligence/observations.csv").write_text(
        "type,value,observed_at\ndomain,bad/host,2026-10-01T00:00:00Z\n"
    )
    assert repo.digest() != initial
    with pytest.raises(ValueError, match="quarantined"):
        repo.build(tmp_path / "builds", kind="feedpack")
    assert repo.build(tmp_path / "builds", kind="codepack")["valid"]
