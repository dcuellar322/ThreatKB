"""Audit every locked Python/npm release against a reproducible minimum age."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, time, timedelta, timezone
import json
import re
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import Version
import requests

ROOT = Path(__file__).resolve().parents[1]


def cutoff_for(as_of, minimum_age_days):
    if minimum_age_days < 10:
        raise ValueError("The minimum release age must be at least ten days.")
    return datetime.combine(
        as_of - timedelta(days=minimum_age_days), time(), timezone.utc
    )


def python_pins(root):
    pins = set()
    for name in ("requirements.txt", "requirements-dev.txt", "requirements-build.txt"):
        path = root / name
        if not path.exists():
            continue
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            requirement = Requirement(line.strip())
            specs = list(requirement.specifier)
            if requirement.url or len(specs) != 1 or specs[0].operator != "==":
                raise ValueError(f"Dependency must have an exact registry pin: {line}")
            version = Version(specs[0].version)
            if version.is_prerelease or version.is_devrelease:
                raise ValueError(f"Prerelease dependency: {line}")
            pins.add((canonicalize_name(requirement.name), str(version)))
    return sorted(pins)


def node_pins(root):
    lock = json.loads((root / "frontend/package-lock.json").read_text())
    pins = set()
    for path, value in lock["packages"].items():
        if "node_modules/" not in path:
            continue
        name = path.rsplit("node_modules/", 1)[1]
        version = value.get("version", "")
        if value.get("link") or not value.get("integrity") or "-" in version:
            raise ValueError(
                f"Dependency needs a stable registry pin and integrity: {name}"
            )
        pins.add((name, version))
    return sorted(pins)


def python_release(item):
    name, version = item
    response = requests.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=45)
    response.raise_for_status()
    files = response.json()["urls"]
    if not files or all(file.get("yanked") for file in files):
        raise ValueError(f"Missing or withdrawn Python release: {name}=={version}")
    return {
        "name": name,
        "version": version,
        "published": min(file["upload_time_iso_8601"] for file in files),
    }


def node_release(item):
    name, version = item
    response = requests.get(
        "https://registry.npmjs.org/" + name.replace("/", "%2f"), timeout=45
    )
    response.raise_for_status()
    data = response.json()
    if version not in data.get("versions", {}):
        raise ValueError(f"Missing npm release: {name}@{version}")
    return {"name": name, "version": version, "published": data["time"][version]}


def validate_evidence(pins, evidence, cutoff):
    actual = {(row["name"], row["version"]) for row in evidence}
    if actual != set(pins) or len(actual) != len(evidence):
        raise ValueError(f"Audit evidence differs from the lock: {set(pins) ^ actual}")
    for row in evidence:
        published = datetime.fromisoformat(row["published"].replace("Z", "+00:00"))
        if published.tzinfo is None or published > cutoff:
            raise ValueError(f"Release is too new for {cutoff.isoformat()}: {row}")


def validate_infrastructure(root, cutoff):
    evidence = json.loads(
        (root / "docs/infrastructure-dependency-audit.json").read_text()
    )
    references = {}
    for row in evidence:
        key = (row["kind"], row["name"])
        if key in references:
            raise ValueError(f"Duplicate infrastructure evidence: {key}")
        references[key] = row
        published = datetime.fromisoformat(row["published"].replace("Z", "+00:00"))
        if published.tzinfo is None or published > cutoff:
            raise ValueError(f"Infrastructure dependency is too new: {row}")
    dockerfile = (root / "Dockerfile").read_text()
    stages = set()
    for line in dockerfile.splitlines():
        if not line.startswith("FROM "):
            continue
        parts = line.split()
        reference = parts[1]
        if reference not in stages:
            name = reference.split(":", 1)[0]
            row = references[("image", name)]
            if reference != f"{name}:{row['version']}@{row['digest']}":
                raise ValueError(
                    f"Container pin differs from its age evidence: {reference}"
                )
        if len(parts) > 3 and parts[2].upper() == "AS":
            stages.add(parts[3])
    import yaml

    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    for service in compose["services"].values():
        reference = service.get("image")
        if reference:
            name = reference.split(":", 1)[0]
            row = references[("image", name)]
            if reference != f"{name}:{row['version']}@{row['digest']}":
                raise ValueError(
                    f"Service pin differs from its age evidence: {reference}"
                )
    for path in (root / ".github/workflows").glob("*.yml"):
        for name, commit in re.findall(
            r"uses:\s+([\w./-]+)@([\w.-]+)", path.read_text()
        ):
            row = references[("action", name)]
            if commit != row["commit"] or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise ValueError(
                    f"Action must use its audited immutable commit: {name}"
                )
    snapshots = re.findall(
        r"snapshot.debian.org/archive/[^/]+/(\d{8}T\d{6}Z)/", dockerfile
    )
    if not snapshots or any(
        datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc) > cutoff
        for stamp in snapshots
    ):
        raise ValueError("Debian package snapshots must predate the cutoff.")
    return len(references)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--as-of", type=date.fromisoformat, default=datetime.now(timezone.utc).date()
    )
    parser.add_argument("--minimum-age-days", type=int, default=10)
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Check the locks against recorded registry evidence",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Query registries without rewriting evidence",
    )
    args = parser.parse_args()
    cutoff = cutoff_for(args.as_of, args.minimum_age_days)
    counts = []
    for pins, fetch, filename in [
        (python_pins(ROOT), python_release, "python-dependency-audit.json"),
        (node_pins(ROOT), node_release, "frontend-dependency-audit.json"),
    ]:
        path = ROOT / "docs" / filename
        if args.offline:
            evidence = json.loads(path.read_text())
        else:
            with ThreadPoolExecutor(max_workers=8) as pool:
                evidence = list(pool.map(fetch, pins))
        validate_evidence(pins, evidence, cutoff)
        if not args.offline and not args.check:
            path.write_text(json.dumps(evidence, indent=2) + "\n")
        counts.append(len(pins))
    infrastructure = validate_infrastructure(ROOT, cutoff)
    print(
        f"Verified {counts[0]} Python and {counts[1]} npm releases plus {infrastructure} infrastructure pins on/before {cutoff.isoformat()}"
    )


if __name__ == "__main__":
    main()
