from app.dev_seed import seed_database
from app.models.yara_rule import Yara_rule
import yaml
import yara


def test_seed_is_repeatable_and_emits_compilable_yaml(client, tmp_path):
    assert seed_database(
        1, rules=3, ips=4, domains=2, tasks=1, content_dir=tmp_path
    ) == {"rules": 3, "ips": 4, "domains": 2, "tasks": 1}
    assert seed_database(1, rules=3, ips=4, domains=2, tasks=1) == {
        "rules": 0,
        "ips": 0,
        "domains": 0,
        "tasks": 0,
    }
    assert Yara_rule.query.count() == 3
    document = yaml.safe_load(next((tmp_path / "rules").glob("*.yaml")).read_text())
    compiled = yara.compile(
        source=f"rule test {{ strings: {document['strings']} condition: {document['condition']} }}"
    )
    marker = document["strings"].split('"')[1]
    assert compiled.match(data=marker.encode())
