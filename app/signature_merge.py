"""Merge parsed YARA sections without rewriting string payloads or quantifier scope."""

import re
from app.utilities import extract_yara_rules_text
from app.models.yara_rule import Yara_rule
from app.detection import validate_signature

TOKENS = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|/(?:\\.|[^/\\\n])+/[a-z]*|[$#@!][A-Za-z_]\w*\*?|\bthem\b',
    re.S,
)


def merge_sources(sources, name):
    parsed = extract_yara_rules_text("\n\n".join(sources))
    if len(parsed) < 2 or len(parsed) > 20:
        raise ValueError("Choose between 2 and 20 signatures.")
    strings = []
    conditions = []
    imports = []
    for index, rule in enumerate(parsed, 1):
        prefix = f"r{index}_"

        def replace(match, prefix=prefix):
            token = match.group()
            if token == "them":
                return f"(${prefix}*)"
            if token[0] in "$#@!":
                return token[0] + prefix + token[1:]
            return token

        strings.append(TOKENS.sub(replace, rule["strings"]))
        conditions.append("(" + TOKENS.sub(replace, rule["condition"]) + ")")
        imports.extend(Yara_rule.get_imports_from_string(rule["imports"]).splitlines())
    value = {
        "name": name,
        "strings": "\n".join(strings),
        "condition": " or ".join(conditions),
        "imports": "\n".join(sorted(set(imports))),
    }
    validate_signature(value)
    return value
