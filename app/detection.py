"""Compile active signatures together in dependency order."""

import re
import yara
from functools import lru_cache
from app.models.yara_rule import Yara_rule
from app.models.cfg_states import Cfg_states


def _source(values, include_imports=False):
    strings = re.sub(r"^\s*strings:\s*", "", values.get("strings") or "")
    condition = re.sub(r"^\s*condition:\s*", "", values.get("condition") or "false")
    body = f"rule {values['name']} {{\n"
    if strings.strip():
        body += f"strings:\n{strings}\n"
    body += f"condition:\n{condition}\n}}\n"
    return Yara_rule.expand_macros(body)


def _payload(row):
    return {
        key: getattr(row, key) for key in ("name", "strings", "condition", "imports")
    }


def combined_source(values, targets=None):
    by_name = {item["name"]: item for item in values}
    emitted, visiting, ordered = set(), set(), []

    def visit(name):
        if name in visiting:
            raise ValueError(f"Circular rule reference involving {name}")
        if name in emitted:
            return
        visiting.add(name)
        condition = Yara_rule.expand_macros(by_name[name].get("condition") or "")
        dependencies = (
            set(re.findall(r"(?<![$\w])[A-Za-z_]\w*", condition)) & by_name.keys()
        )
        for dependency in sorted(dependencies):
            visit(dependency)
        visiting.remove(name)
        emitted.add(name)
        ordered.append(by_name[name])

    for name in targets or sorted(by_name):
        visit(name)
    imports = {
        module
        for item in ordered
        for module in re.findall(r'import\s+"(\w+)"', item.get("imports") or "")
    }
    return "\n".join(
        [
            *(f'import "{module}"' for module in sorted(imports)),
            *(_source(item) for item in ordered),
        ]
    )


def active_values(owner_id=None):
    query = Yara_rule.query.with_entities(
        Yara_rule.name, Yara_rule.strings, Yara_rule.condition, Yara_rule.imports
    ).filter(Yara_rule.active.is_(True))
    if owner_id is not None:
        query = query.filter(Yara_rule.owner_user_id == owner_id)
    return tuple(tuple(row) for row in query.order_by(Yara_rule.name))


def active_rule_source(owner_id=None):
    return combined_source(
        [
            dict(zip(("name", "strings", "condition", "imports"), row))
            for row in active_values(owner_id)
        ]
    )


@lru_cache(maxsize=4)
def _compiled_active(values, replacements):
    source = combined_source(
        [dict(zip(("name", "strings", "condition", "imports"), row)) for row in values]
    )
    return yara.compile(source=source)


def compile_active_rules(owner_id=None):
    from app.macro_expansion import macro_replacements

    return _compiled_active(active_values(owner_id), macro_replacements())


def validate_signature(candidate, exclude_id=None):
    release = Cfg_states.query.filter_by(is_release_state=1).first()
    query = Yara_rule.query.filter(Yara_rule.active.is_(True))
    if release:
        query = query.filter_by(state=release.state)
    if exclude_id:
        query = query.filter(Yara_rule.id != exclude_id)
    existing = [_payload(row) for row in query if row.name != candidate["name"]]
    return yara.compile(
        source=combined_source([*existing, candidate], targets=[candidate["name"]])
    )
