"""Deterministic synthetic data for local scale and workflow verification."""
from datetime import datetime, timedelta
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from uuid import uuid5, NAMESPACE_URL
import json
import subprocess
import click
import yaml
from app import app, db, cache
from app.models.users import KBUser
from app.models.yara_rule import Yara_rule, Yara_rule_history
from app.models.c2ip import C2ip
from app.models.c2dns import C2dns
from app.models.tasks import Tasks
from app.models.cfg_states import Cfg_states
from app.models.activity_log import ActivityLog


def seed_database(user_id, rules=2500, ips=10000, domains=5000, tasks=400, content_dir=None):
    states = ["Imported", "Vetting", "Released", "Retired"]
    existing_states = {row.state for row in Cfg_states.query.all()}
    for state in states:
        if state not in existing_states:
            db.session.execute(Cfg_states.__table__.insert().values(
                state=state, is_release_state=int(state == "Released"),
                is_staging_state=int(state == "Vetting"), is_retired_state=int(state == "Retired")))
    now = datetime(2026, 10, 1, 12)
    common = dict(created_user_id=user_id, modified_user_id=user_id, owner_user_id=user_id)
    rule_names = set(db.session.scalars(db.select(Yara_rule.name)))
    added = {"rules": 0, "ips": 0, "domains": 0, "tasks": 0}
    if content_dir:
        content_dir = Path(content_dir)
        (content_dir / "rules").mkdir(parents=True, exist_ok=True)
        corpus = Path(app.instance_path) / "dev-corpus"
        corpus.mkdir(parents=True, exist_ok=True)
    for index in range(rules):
        name = f"DEV_Synthetic_Indicator_{index:05}"
        marker = f"THREATKB_DEVELOPMENT_{index:05}"
        payload = f"Benign development fixture. {marker}.\n".encode()
        digest = sha256(payload).hexdigest()
        state = states[index % len(states)]
        timestamp = now - timedelta(hours=index % 1000)
        if name not in rule_names:
            values = dict(name=name, uuid=str(uuid5(NAMESPACE_URL, f"threatkb:dev:{index}")), eventid=700000000 + index, category="Development",
                          strings=f'$marker = "{marker}" ascii', condition="$marker",
                          description=f"Synthetic fixture {index}: workflow and scale verification — no real threat data.",
                          references="https://example.test/development", state=state, revision=1,
                          creation_date=timestamp, last_revision_date=timestamp, active=True, **common)
            result = db.session.execute(Yara_rule.__table__.insert().values(**values))
            rule_id = result.inserted_primary_key[0]
            snapshot = {**values, "id": rule_id, "creation_date": timestamp.isoformat(),
                        "last_revision_date": timestamp.isoformat(), "metadata": {}, "metadata_values": {}}
            db.session.add(Yara_rule_history(yara_rule_id=rule_id, revision=1, user_id=user_id,
                                             state=state, date_created=timestamp, rule_json=json.dumps(snapshot)))
            db.session.execute(ActivityLog.__table__.insert().values(activity_type="ARTIFACT_CREATED",
                activity_text=name, activity_date=timestamp, entity_type=1, entity_id=rule_id, user_id=user_id))
            added["rules"] += 1
        if content_dir:
            document = {"id": str(uuid5(NAMESPACE_URL, f"threatkb:dev:{index}")), "name": name,
                        "category": "DEV", "status": state.lower(),
                        "description": f"Synthetic development fixture {index}",
                        "tags": ["source:synthetic", f"testing:cohort={index % 10}"],
                        "strings": f'$marker = "{marker}" ascii', "condition": "$marker",
                        "references": {"public": {"samples": [digest]}},
                        "testing_strategy": ["match_all_referenced_samples"]}
            (content_dir / "rules" / f"{name}.yaml").write_text(yaml.safe_dump(document, sort_keys=False))
            (corpus / digest).write_bytes(payload)
    for model, count, column, key in ((C2ip, ips, "ip", "ips"), (C2dns, domains, "domain_name", "domains"),
                                       (Tasks, tasks, "title", "tasks")):
        existing = set(db.session.scalars(db.select(getattr(model, column))))
        values = []
        for index in range(count):
            value = (str(ip_address(int(ip_address("198.18.0.0")) + index)) if model is C2ip
                     else f"fixture-{index:05}.example.test" if model is C2dns
                     else f"DEV Review synthetic signature {index:05}")
            if value in existing:
                continue
            row = {column: value, "state": states[index % 4], "active": True,
                   "description": "Synthetic local development data", **common}
            if model is C2dns:
                row["match_type"] = "exact"
            values.append(row)
        if values:
            db.session.execute(model.__table__.insert(), values)
        added[key] = len(values)
    db.session.commit()
    cache.clear()
    return added


@app.cli.command("seed-dev")
@click.option("--email", required=True)
@click.option("--rules", default=2500, type=click.IntRange(1, 10000))
@click.option("--ips", default=10000, type=click.IntRange(0, 100000))
@click.option("--domains", default=5000, type=click.IntRange(0, 100000))
@click.option("--tasks", default=400, type=click.IntRange(0, 10000))
def seed_dev(email, rules, ips, domains, tasks):
    """Add repeatable synthetic fixtures and an independent local Git content repo."""
    user = KBUser.query.filter_by(email=email).first()
    if not user:
        raise click.ClickException("Create the local administrator first.")
    content = Path(app.instance_path) / "dev-content"
    result = seed_database(user.id, rules, ips, domains, tasks, content)
    if not (content / ".git").exists():
        subprocess.run(["git", "init", "-b", "main", str(content)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(content), "add", "rules"], check=True)
    changed = subprocess.run(["git", "-C", str(content), "diff", "--cached", "--quiet"]).returncode
    if changed:
        subprocess.run(["git", "-C", str(content), "-c", "user.name=ThreatKB Development",
                        "-c", "user.email=development@example.test", "commit", "-m", "Seed synthetic development signatures"],
                       check=True, capture_output=True)
    click.echo(json.dumps({"added": result, "content_repository": str(content),
                           "sample_corpus": str(Path(app.instance_path) / "dev-corpus")}))
