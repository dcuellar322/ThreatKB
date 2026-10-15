from app.compat import strtobool
import re
import json
import sys

from flask_login import current_user
from plyara import Plyara

from more_itertools import unique_everseen
from sqlalchemy import and_, not_, or_, text, select, exists
from sqlalchemy import DateTime
from datetime import datetime

from app import ENTITY_MAPPING
from app.models import cfg_settings
from app.models.comments import Comments
from app.models.c2dns import C2dns
from app.models.c2ip import C2ip
from app.models.metadata import Metadata, MetadataMapping
from app.models.tags_mapping import Tags_mapping
from app.models.tags import Tags
from app.models.users import KBUser
from app.models.yara_rule import Yara_rule


#####################################################################


def extract_ips_text(text):
    regex = cfg_settings.Cfg_settings.get_setting(key="IMPORT_IP_REGEX")
    ip_regex = regex if regex else r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,3})?)"
    return re.compile(ip_regex).findall(text.replace("[.]", "."))


#####################################################################


def extract_dns_text(text):
    hostnames = []
    regex = cfg_settings.Cfg_settings.get_setting(key="IMPORT_DNS_REGEX")
    url_regex = (
        regex
        if regex
        else r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    )
    for dns in re.compile(url_regex).findall(text.replace("[.]", ".")):
        try:
            hostnames.append(dns)
        except:
            pass
    return hostnames


#####################################################################


def extract_yara_rules_text(text):
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if not re.search(r"\brule\s+[A-Za-z_]", text):
        return []
    from flask import abort

    try:
        parsed = Plyara().parse_string(text)
    except Exception as error:
        abort(422, description=f"Could not parse YARA input: {error}")
    imports = Yara_rule.get_imports_from_string(text)
    return [
        {
            "parsed_rule": rule,
            "strings": re.sub(r"^\s*strings:\s*", "", rule.get("raw_strings", "")),
            "condition": re.sub(r"^\s*condition:\s*", "", rule["raw_condition"]),
            "imports": imports,
        }
        for rule in parsed
    ]


#####################################################################


def filter_entities(
    entity,
    artifact_type,
    searches,
    page_number,
    page_size,
    sort_by,
    sort_direction,
    include_metadata,
    include_tags,
    include_comments,
    exclude_totals,
    default_sort,
    include_inactive=False,
    include_active=True,
    include_merged=False,
    include_yara_string=None,
    short=None,
    operator="and",
    since=None,
):
    from app.querying import filter_page

    return filter_page(**locals())


#####################################################################


def get_strings_and_conditions(rule):
    segment_headers = {
        "strings": "^\\s*strings:\\s*\r?\n?",
        "condition": "^\\s*condition:\\s*\r?\n?",
    }
    segments = {
        "strings": [],
        "condition": [],
    }
    SEGMENT = None
    for line in rule.splitlines():
        segment_change = False
        for header, rx in list(segment_headers.items()):
            if re.match(rx, line):
                SEGMENT = header
                segment_change = True
        if SEGMENT and not segment_change:
            segments[SEGMENT].append(line)

    if segments.get("strings", None):
        segments["strings"][-1] = (
            segments["strings"][-1].rstrip(" }")
            if not "=" in segments["strings"][-1]
            else segments["strings"][-1]
        )

    if segments.get("condition", None):
        segments["condition"][-1] = segments["condition"][-1].rstrip().rstrip(" }\n\t")

    return "\n".join(segments["strings"]) if segments.get(
        "strings", None
    ) else "", "\n".join(
        [segment for segment in segments["condition"] if segment.strip(" }")]
    )


#####################################################################


def extract_artifacts_by_type(type_, import_objects):
    table_mapping = {"ip": C2ip, "domain_name": C2dns}
    output = []
    processed = set()

    for import_object in import_objects:
        if import_object[type_] in processed:
            continue

        processed.add(import_object[type_])
        temp_object = {"type": type_, "metadata": {}, "artifact": import_object[type_]}
        for key, val in import_object.items():
            if key.lower() == type_ or key.lower() == "artifact":
                continue
            elif key in list(table_mapping[type_].__table__.columns.keys()):
                temp_object[key] = val
            else:
                temp_object["metadata"][key] = val

        output.append(temp_object)

    return output


#####################################################################


def extract_artifacts_json(
    do_extract_ip, do_extract_dns, do_extract_signature, import_objects
):
    ips = extract_artifacts_by_type(
        "ip",
        [import_object for import_object in import_objects if "ip" in import_object],
    )
    dns = extract_artifacts_by_type(
        "domain_name",
        [
            import_object
            for import_object in import_objects
            if "domain_name" in import_object
        ],
    )
    temp = []
    output = []

    if do_extract_ip:
        output.extend(ips)
    if do_extract_dns:
        output.extend(dns)

    return output


#####################################################################


def extract_artifacts_text(do_extract_ip, do_extract_dns, do_extract_signature, text):
    ips = extract_ips_text(text)
    dns = extract_dns_text(text)
    yara_rules = extract_yara_rules_text(text)
    temp = []
    output = []

    if do_extract_ip:
        output.extend(
            [{"type": "IP", "artifact": ip} for ip in list(unique_everseen(ips))]
        )
    if do_extract_dns:
        output.extend(
            [
                {"type": "DNS", "artifact": hostname}
                for hostname in list(unique_everseen(dns))
            ]
        )
    if do_extract_signature:
        for yara_rule in yara_rules:
            yr = yara_rule["parsed_rule"]  # hacky
            if not yr["rule_name"] in temp:
                temp.append(yr["rule_name"])
                output.append(
                    {
                        "type": "YARA_RULE",
                        "artifact": yr["rule_name"],
                        "rule": yr,
                        "strings": yara_rule["strings"],
                        "condition": yara_rule["condition"],
                        "imports": yara_rule["imports"],
                    }
                )

    return output


#####################################################################


def extract_artifacts(do_extract_ip, do_extract_dns, do_extract_signature, text):
    try:
        import_objects = json.loads(str(text))
        return extract_artifacts_json(
            do_extract_ip, do_extract_dns, do_extract_signature, import_objects
        )
    except ValueError as e:
        try:
            import_objects = json.loads(str(text))
            return extract_artifacts_json(
                do_extract_ip, do_extract_dns, do_extract_signature, import_objects
            )
        except ValueError as e:
            return extract_artifacts_text(
                do_extract_ip, do_extract_dns, do_extract_signature, text
            )


#####################################################################


def parse_yara_rules_file(filename):
    return parse_yara_rules_text(open(filename, "r").read())


#####################################################################


def parse_yara_rules_text(text):
    return Plyara().parse_string(text)


#####################################################################
