"""Offline indicator assessment with provenance, explicit policy and review decisions."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import csv
import ipaddress
import json
from pathlib import Path
import re
from uuid import NAMESPACE_URL, uuid5

from .engine import ContentError, load

MAX_INPUT_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 100_000


def read_input(path):
    path = Path(path)
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ContentError("Indicator input exceeds 10 MiB")
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as stream:
            records = list(csv.DictReader(stream))
    elif path.suffix.lower() == ".json":
        records = json.loads(path.read_text())
    else:
        records = load(path)
    if isinstance(records, dict):
        records = records.get("indicators")
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ContentError("Indicator input must be a list of at most 100,000 records")
    return records


def normalize(kind, value):
    if not isinstance(value, str) or not value.strip() or len(value) > 253:
        raise ValueError("Indicator value must contain 1–253 characters")
    value = value.strip()
    if kind == "ip":
        return str(ipaddress.ip_address(value))
    if kind != "domain":
        raise ValueError("Supported indicator types are ip and domain")
    value = value.removesuffix(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if (
        len(labels) < 2
        or len(value) > 253
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        )
    ):
        raise ValueError("Invalid domain name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("An IP address must use type ip")


def timestamp(value):
    result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Observation times must include a timezone")
    return result.astimezone(timezone.utc)


def score(value):
    if isinstance(value, str) and re.fullmatch(r"\d{1,3}", value):
        value = int(value)
    if type(value) is not int or not 0 <= value <= 100:
        raise ValueError("Confidence and severity must be integers from 0 to 100")
    return value


def context_matches(kind, value, context):
    if kind == "ip" and "network" in context:
        return ipaddress.ip_address(value) in ipaddress.ip_network(context["network"])
    if kind == "domain" and "domain_suffix" in context:
        suffix = normalize("domain", context["domain_suffix"])
        return value == suffix or value.endswith("." + suffix)
    return False


def evaluate(
    observations, sources, policy=None, enrichment=None, decisions=None, now=None
):
    """Return an auditable warehouse snapshot and only approved, eligible exports.

    Source trust caps are authoritative; untrusted record scores cannot raise them.
    Review decisions are local Git-managed assertions, bound to the record digest.
    This function performs no network lookups or sample execution.
    """
    policy, enrichment, decisions = policy or {}, enrichment or [], decisions or {}
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ContentError("Evaluation time must include a timezone")
    if not isinstance(sources, dict) or not sources:
        raise ContentError("Configure at least one named indicator source")
    if not isinstance(observations, list) or len(observations) > MAX_RECORDS:
        raise ContentError("At most 100,000 observations can be evaluated")
    try:
        for key in ("require_review", "allow_non_global_ips"):
            if key in policy and type(policy[key]) is not bool:
                raise ValueError(f"{key} must be a boolean")
        minimum = score(policy.get("min_confidence", 70))
        max_age = int(policy.get("max_age_days", 90))
        if max_age <= 0:
            raise ValueError("Maximum age must be positive")
        for context in [*enrichment, *policy.get("allowlist", [])]:
            if "network" in context:
                ipaddress.ip_network(context["network"])
            elif "domain_suffix" in context:
                normalize("domain", context["domain_suffix"])
            else:
                raise ValueError("Context needs a network or domain_suffix")
    except (ValueError, TypeError) as error:
        raise ContentError(f"Invalid intelligence policy: {error}") from error
    grouped, invalid, normalized = {}, [], []
    for index, raw in enumerate(observations):
        try:
            if not isinstance(raw, dict):
                raise ValueError("Indicator observation must be an object")
            source_name = raw.get("source")
            source = sources.get(source_name)
            if not isinstance(source, dict) or not source.get("enabled", True):
                raise ValueError("Unknown or disabled indicator source")
            kind, value = raw.get("type"), normalize(raw.get("type"), raw.get("value"))
            observed = timestamp(raw["observed_at"])
            if observed > now:
                raise ValueError("Observation time is in the future")
            expires = timestamp(raw["expires_at"]) if raw.get("expires_at") else None
            source_age = int(source.get("max_age_days", max_age))
            if source_age <= 0:
                raise ValueError("Source maximum age must be positive")
            groups = raw.get("groups") or source.get("groups", ["default"])
            if isinstance(groups, str):
                groups = [part.strip() for part in groups.split(",") if part.strip()]
            if (
                not isinstance(groups, list)
                or not groups
                or not set(groups) <= set(source.get("groups", ["default"]))
            ):
                raise ValueError("Indicator groups must be allowed by its source")
            tags = raw.get("tags", [])
            if isinstance(tags, str):
                tags = [part.strip() for part in tags.split(",") if part.strip()]
            if not isinstance(tags, list) or any(
                not isinstance(tag, str) or len(tag) > 256 for tag in tags
            ):
                raise ValueError("Tags must be a list of strings up to 256 characters")
            status = raw.get("status", "candidate")
            if status not in ("candidate", "released", "retired"):
                raise ValueError("Unknown indicator status")
            item = dict(
                type=kind,
                value=value,
                source=source_name,
                observed_at=observed.isoformat(),
                expires_at=expires.isoformat() if expires else None,
                confidence=min(
                    score(raw.get("confidence", source.get("confidence", 0))),
                    score(source.get("confidence", 0)),
                ),
                severity=score(raw.get("severity", source.get("severity", 50))),
                groups=sorted(set(groups)),
                tags=sorted(set(tags)),
                status=status,
                stale=now - observed > timedelta(days=min(max_age, source_age)),
            )
            normalized.append(
                {key: value for key, value in item.items() if key != "stale"}
            )
            grouped.setdefault((kind, value), []).append(item)
        except (ValueError, TypeError, KeyError, UnicodeError) as error:
            invalid.append({"index": index, "reason": str(error), "observation": raw})
    result = {
        "released": [],
        "held": [],
        "retired": [],
        "invalid": invalid,
        "observations": normalized,
        "evaluated_at": now.isoformat(),
    }
    for (kind, value), items in sorted(grouped.items()):
        identity = str(uuid5(NAMESPACE_URL, f"threatkb:ioc:{kind}:{value}"))
        # A source's latest observation supersedes its older disposition and expiry.
        latest = {}
        for item in sorted(
            items,
            key=lambda item: (item["observed_at"], json.dumps(item, sort_keys=True)),
        ):
            latest[item["source"]] = item
        active = [
            item
            for item in latest.values()
            if item["status"] != "retired"
            and (not item["expires_at"] or timestamp(item["expires_at"]) > now)
        ]
        eligible = [item for item in active if not item["stale"]]
        provenance = sorted(latest.values(), key=lambda item: item["source"])
        digest = sha256(
            json.dumps(
                [
                    {key: val for key, val in item.items() if key != "stale"}
                    for item in provenance
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        record = dict(
            id=identity,
            type=kind,
            value=value,
            record_digest=digest,
            confidence=max((item["confidence"] for item in eligible), default=0),
            severity=max((item["severity"] for item in eligible), default=0),
            groups=sorted(
                {
                    group
                    for item in eligible
                    if item["confidence"] >= minimum
                    for group in item["groups"]
                }
            ),
            tags=sorted({tag for item in eligible for tag in item["tags"]}),
            first_seen=min(item["observed_at"] for item in items),
            last_seen=max(item["observed_at"] for item in items),
            provenance=provenance,
            enrichment=[
                context
                for context in enrichment
                if context_matches(kind, value, context)
            ],
        )
        reasons = []
        conflicting = any(
            len(
                {
                    json.dumps(item, sort_keys=True)
                    for item in items
                    if item["source"] == source
                    and item["observed_at"] == latest_item["observed_at"]
                }
            )
            > 1
            for source, latest_item in latest.items()
        )
        decision = decisions.get(identity, {})
        if not active or decision.get("decision") == "retired":
            destination = "retired"
            reasons.append("retired or expired")
        else:
            if conflicting:
                reasons.append("source has conflicting observations at the same time")
            if not eligible:
                reasons.append("observations are stale")
            if record["confidence"] < minimum:
                reasons.append("confidence is below policy threshold")
            if (
                kind == "ip"
                and not policy.get("allow_non_global_ips", False)
                and not ipaddress.ip_address(value).is_global
            ):
                reasons.append("IP is not globally routable")
            if any(
                context_matches(kind, value, entry)
                for entry in policy.get("allowlist", [])
            ):
                reasons.append("indicator is allowlisted")
            approved = (
                decision.get("decision") == "approved"
                and decision.get("record_digest") == digest
                and decision.get("author")
                and decision.get("reviewer")
                and decision["author"] != decision["reviewer"]
            )
            if decision.get("decision") == "rejected":
                reasons.append("review rejected")
            elif policy.get("require_review", True) and not approved:
                reasons.append("independent review of this record digest is required")
            destination = "held" if reasons else "released"
        record.update(
            status="released" if destination == "released" else destination,
            reasons=reasons,
        )
        result[destination].append(record)
    result["summary"] = {
        key: len(result[key]) for key in ("released", "held", "retired", "invalid")
    }
    result["summary"]["observations"] = len(normalized)
    return result


def assess_repository(root):
    """Evaluate a repository's opt-in intelligence/pipeline.yaml configuration."""
    root = Path(root).resolve()
    config = load(root / "intelligence/pipeline.yaml")
    if not isinstance(config, dict):
        raise ContentError("Intelligence pipeline must be a configuration mapping")

    def path(key, required=False):
        value = config.get(key)
        if not value:
            if required:
                raise ContentError(f"Intelligence pipeline requires {key}")
            return None
        target = (root / value).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            raise ContentError(
                f"Intelligence {key} must be a file within the repository"
            )
        return target

    records = read_input(path("input", True))
    source = config.get("source")
    observations = [
        {**row, "source": source} if isinstance(row, dict) else row for row in records
    ]
    report = evaluate(
        observations,
        load(path("sources", True)),
        load(path("policy")) if config.get("policy") else {},
        load(path("enrichment")) if config.get("enrichment") else [],
        load(path("decisions")) if config.get("decisions") else {},
    )
    if report["invalid"]:
        raise ContentError(
            f"Intelligence pipeline quarantined {len(report['invalid'])} malformed observations"
        )
    return report
