"""Shared compilation of active signatures, including cross-rule references."""
import re
import yara
from app.models.yara_rule import Yara_rule


def active_rule_source():
    imports, rules = set(), []
    for rule in Yara_rule.query.filter_by(active=True).order_by(Yara_rule.id):
        imports.update(re.findall(r'import\s+"(\w+)"', rule.imports or ""))
        strings = re.sub(r"^\s*strings:\s*", "", rule.strings or "")
        condition = re.sub(r"^\s*condition:\s*", "", rule.condition or "false")
        body = f"rule {rule.name} {{\n"
        if strings.strip():
            body += f"strings:\n{strings}\n"
        body += f"condition:\n{condition}\n}}\n"
        rules.append(Yara_rule.expand_macros(body))
    return "\n".join([*(f'import "{name}"' for name in sorted(imports)), *rules])


def compile_active_rules():
    return yara.compile(source=active_rule_source())
