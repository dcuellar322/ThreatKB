"""Verify locked application releases against the ten-day stability cutoff."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import json
import requests

ROOT = Path(__file__).resolve().parents[1]
CUTOFF = datetime(2026, 10, 5, tzinfo=timezone.utc)


def python_release(item):
    name, version = item
    response = requests.get(f"https://pypi.org/pypi/{name}/{version}/json", timeout=45)
    response.raise_for_status()
    published = min(file["upload_time_iso_8601"] for file in response.json()["urls"])
    return {"name": name, "version": version, "published": published}


def node_release(item):
    name, version = item
    response = requests.get(
        "https://registry.npmjs.org/" + name.replace("/", "%2f"), timeout=45
    )
    response.raise_for_status()
    return {
        "name": name,
        "version": version,
        "published": response.json()["time"][version],
    }


def main():
    python = [
        tuple(line.strip().split("=="))
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if "==" in line and not line.lstrip().startswith("#")
    ]
    lock = json.loads((ROOT / "frontend/package-lock.json").read_text())
    node = set()
    for path, value in lock["packages"].items():
        if "node_modules/" in path:
            node.add((path.rsplit("node_modules/", 1)[1], value["version"]))
    with ThreadPoolExecutor(max_workers=8) as pool:
        py = list(pool.map(python_release, python))
        js = list(pool.map(node_release, sorted(node)))
    for value in [*py, *js]:
        if datetime.fromisoformat(value["published"].replace("Z", "+00:00")) >= CUTOFF:
            raise ValueError(f"Release is too new: {value}")
    (ROOT / "docs/python-dependency-audit.json").write_text(
        json.dumps(py, indent=2) + "\n"
    )
    (ROOT / "docs/frontend-dependency-audit.json").write_text(
        json.dumps(js, indent=2) + "\n"
    )
    print(
        f"Verified {len(py)} Python and {len(js)} npm releases before {CUTOFF.isoformat()}"
    )


if __name__ == "__main__":
    main()
