from ipaddress import ip_address
from urllib.parse import urlsplit
from flask import abort
from flask_login import current_user
from app import db
from app.models.c2ip import C2ip
from app.models.c2dns import C2dns
from app.models.cfg_states import Cfg_states


def retire_imported_indicators(artifacts):
    released = Cfg_states.query.filter_by(is_release_state=1).first()
    retired = Cfg_states.query.filter_by(is_retired_state=1).first()
    if not released or not retired:
        abort(400, description="Configure release and retirement states first.")
    result = {
        "retired": [],
        "skipped": [],
        "not_found": [],
        "errors": [],
        "committed": [],
        "duplicates": [],
        "resurrected": [],
    }
    for artifact in artifacts:
        kind = artifact.get("type", "").lower()
        value = artifact.get("artifact", "")
        if kind not in ("ip", "dns", "domain_name"):
            result["skipped"].append(value)
            continue
        try:
            if kind == "ip":
                value = str(ip_address(value))
                entity = C2ip.query.filter_by(ip=value).first()
            else:
                value = (
                    (urlsplit(value).hostname if "://" in value else value)
                    .lower()
                    .rstrip(".")
                )
                entity = C2dns.query.filter_by(domain_name=value).first()
        except ValueError, AttributeError:
            result["errors"].append([value, "Invalid indicator"])
            continue
        if not entity:
            result["not_found"].append(value)
        elif entity.state != released.state:
            result["skipped"].append(value)
        elif not current_user.admin and entity.owner_user_id != current_user.id:
            result["errors"].append([value, "Not authorized to retire this indicator"])
        else:
            entity.state = retired.state
            entity.modified_user_id = current_user.id
            result["retired"].append(value)
    db.session.commit()
    return result
