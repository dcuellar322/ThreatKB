from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import UUID, uuid4
import fcntl
import ipaddress
import json
import re
import subprocess
import zipfile
import yaml
import yara
from jinja2 import StrictUndefined, nodes, TemplateError
from jinja2.sandbox import SandboxedEnvironment
from jsonschema import validate, FormatChecker, Draft202012Validator

RULE_SCHEMA = {
    "type": "object",
    "required": ["id", "name", "category", "strings", "condition"],
    "properties": {
        "id": {"type": "string", "format": "uuid"},
        "name": {"type": "string", "pattern": r"^[A-Za-z_]\w*$"},
        "category": {"type": "string"},
        "strings": {"type": "string", "maxLength": 65536},
        "condition": {"type": "string", "maxLength": 65536},
        "tags": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
        "severity": {"type": "integer", "minimum": 0, "maximum": 100},
        "groups": {"type": "array", "items": {"type": "string"}},
    },
}

RULE_VALIDATOR = Draft202012Validator(RULE_SCHEMA, format_checker=FormatChecker())


class ContentError(ValueError):
    pass


class UniqueLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):
    pass


def mapping(loader, node, deep=False):
    pairs = loader.construct_pairs(node, deep=deep)
    if len({key for key, value in pairs}) != len(pairs):
        raise ContentError("Duplicate YAML mapping key")
    return dict(pairs)


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def load(path, default=None):
    if not path.exists():
        return default
    return yaml.load(path.read_text(), Loader=UniqueLoader)


def load_rule(path):
    rule = load(path)
    RULE_VALIDATOR.validate(rule)
    return rule


def utcnow():
    return datetime.now(timezone.utc)


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, default=str) + "\n")
    temporary.replace(path)


@contextmanager
def lock(root):
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def regex_chunks(values, max_bytes=512):
    if not isinstance(values, list) or len(values) > 10000:
        raise ContentError("Macro lists are limited to 10,000 values")
    chunks, current, size = [], [], 2
    for value in values:
        escaped = re.escape(str(value)).replace("/", r"\/")
        length = len(escaped.encode()) + 1
        if length > max_bytes - 2:
            raise ContentError("One macro item exceeds the regex budget")
        if size + length > max_bytes and current:
            chunks.append("(" + "|".join(current) + ")")
            current, size = [], 2
        current.append(escaped)
        size += length
    if current:
        chunks.append("(" + "|".join(current) + ")")
    return chunks


def environment():
    env = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)
    env.globals.clear()
    env.filters.update(
        regex_chunks=regex_chunks,
        alternation=lambda values: (
            "(" + "|".join(re.escape(str(v)).replace("/", r"\/") for v in values) + ")"
        ),
        yara_strings=lambda values: "\n".join(
            f"$macro_{i} = {json.dumps(str(v), ensure_ascii=False)}"
            for i, v in enumerate(values)
        ),
    )
    return env


class Repository:
    def __init__(self, root, corpus=None, load_rules=True, rule_loader=None):
        self.root = Path(root).resolve()
        self.corpus = Path(corpus).resolve() if corpus else None
        self.categories = load(
            self.root / "categories.yaml",
            {
                "DEV": "Development",
                "UC": "Uncategorized",
                "SC": "Suspicious Characteristics",
                "MC": "Malicious Code",
                "EC": "Exploitable Content",
            },
        )
        self.macros = load(self.root / "macros.yaml", {}) or {}
        self.policy = load(self.root / "policies.yaml", {}) or {}
        self.groups = self.policy.get(
            "groups", {"default": {"categories": ["*"], "collections": ["internal"]}}
        )
        self.rules = []
        self.env = environment()
        for path in sorted((self.root / "rules").glob("*.yaml")) if load_rules else []:
            rule = (rule_loader or load_rule)(path)
            if rule["category"] not in self.categories:
                raise ContentError(f"Unknown category in {path.name}")
            if any(
                group not in self.groups for group in rule.get("groups", ["default"])
            ):
                raise ContentError("Unknown policy group")
            rule["_path"] = path.name
            self.rules.append(rule)
        ids = [rule["id"] for rule in self.rules]
        names = [self.name(rule) for rule in self.rules]
        if len(set(ids)) != len(ids) or len(set(names)) != len(names):
            raise ContentError("Duplicate UUID or rule name")
        self.pairings = (
            (load(self.root / "pairings.yaml", []) or []) if load_rules else []
        )
        for pair in self.pairings:
            if (
                pair.get("kind") not in ("heater", "cooler")
                or len(pair.get("rule_ids", [])) < 2
                or not set(pair["rule_ids"]) <= set(ids)
            ):
                raise ContentError(
                    "Pairings require heater/cooler kind and known UUID references"
                )

    def name(self, rule):
        prefix = rule["category"] + "_"
        return (
            rule["name"] if rule["name"].startswith(prefix) else prefix + rule["name"]
        )

    def digest(self):
        import os

        root = str(self.root)
        files = []
        for folder, dirs, names in os.walk(root):
            dirs[:] = [name for name in dirs if name != ".git"]
            for name in names:
                if name.rsplit(".", 1)[-1] in (
                    "yaml",
                    "yml",
                    "yar",
                    "yara",
                    "json",
                    "csv",
                ):
                    path = os.path.join(folder, name)
                    if path == os.path.join(root, "review.yaml"):
                        continue
                    info = os.stat(path)
                    files.append(
                        (path, info.st_mtime_ns, info.st_ctime_ns, info.st_size)
                    )
        files.sort()
        signature = tuple(files)
        if getattr(self, "_digest_signature", None) != signature:
            digest = sha256()
            for path, *_ in files:
                digest.update(path[len(root) + 1 :].encode() + b"\0")
                with open(path, "rb") as handle:
                    digest.update(handle.read())
            self._digest_value = digest.hexdigest()
            self._digest_signature = signature
        return self._digest_value

    def render(self, text):
        if not any(marker in text for marker in ("{{", "{%", "{#")):
            # Match Jinja's default newline handling without compiling a template
            # for every literal YARA string and condition in the repository.
            rendered = text.replace("\r\n", "\n").replace("\r", "\n").removesuffix("\n")
            if len(rendered.encode()) > 1024 * 1024:
                raise ContentError("Materialized rule exceeds 1 MiB")
            return rendered
        cache = self.__dict__.setdefault("_render_cache", {})
        if text in cache:
            return cache[text]
        ast = self.env.parse(text)
        for loop in ast.find_all(nodes.For):
            if any(loop.find_all(nodes.For)):
                raise ContentError("Nested template loops are not allowed")
        if list(ast.find_all(nodes.Mul)) or list(ast.find_all(nodes.Pow)):
            raise ContentError("Unbounded template multiplication is not allowed")
        output, length = [], 0
        try:
            for part in self.env.from_string(text).generate(
                macros=self.macros, **self.macros
            ):
                length += len(part.encode())
                if length > 1024 * 1024:
                    raise ContentError("Materialized rule exceeds 1 MiB")
                output.append(part)
        except TemplateError as error:
            raise ContentError(str(error)) from error
        rendered = "".join(output)
        if len(cache) < 512 and len(text) + len(rendered) < 16384:
            cache[text] = rendered
        return rendered

    def selected(self, group="default"):
        if group not in self.groups:
            raise ContentError("Unknown policy group")
        policy = self.groups[group]
        allowed = policy.get("categories", ["*"])
        return [
            rule
            for rule in self.rules
            if group in rule.get("groups", ["default"])
            and ("*" in allowed or rule["category"] in allowed)
            and rule.get("enabled", True)
            and rule.get("status", "draft") not in ("retired", "draft", "imported")
            and rule.get("confidence", 100) >= policy.get("min_confidence", 0)
        ]

    def materialize(self, rules):
        by_name = {self.name(rule): rule for rule in rules}
        emitted, active, output = set(), set(), []
        imports = sorted(
            {module for rule in rules for module in rule.get("imports", [])}
        )

        def visit(name):
            if name in active:
                raise ContentError("Circular rule reference")
            if name in emitted:
                return
            active.add(name)
            rule = by_name[name]
            condition = self.render(rule["condition"])
            for dependency in sorted(
                set(re.findall(r"(?<![$\w])[A-Za-z_]\w*", condition)) & by_name.keys()
            ):
                visit(dependency)
            metadata = {
                **rule.get("metadata", {}),
                "id": rule["id"],
                "category": self.categories[rule["category"]],
                "confidence": rule.get("confidence", 100),
                "severity": rule.get("severity", 50),
                "description": rule.get("description", ""),
            }
            metadata.update(
                {f"tag_{i}": tag for i, tag in enumerate(rule.get("tags", []))}
            )
            lines = [f"rule {name} {{", "meta:"]
            for key, value in sorted(metadata.items()):
                key = re.sub(r"\W", "_", key)
                if not key or key[0].isdigit():
                    key = "meta_" + key
                lines.append(f"  {key} = {json.dumps(value, ensure_ascii=False)}")
            strings = self.render(rule["strings"]).strip()
            if strings:
                lines += ["strings:", strings]
            lines += ["condition:", condition, "}"]
            output.append("\n".join(lines))
            active.remove(name)
            emitted.add(name)

        for name in sorted(by_name):
            visit(name)
        return (
            "\n".join([*(f'import "{module}"' for module in imports), *output]) + "\n"
        )

    def collections(self, group):
        sources = {}
        allowed = self.groups[group].get("collections", ["internal"])
        for collection in load(self.root / "collections.yaml", []) or []:
            if (
                not collection.get("enabled", False)
                or collection["name"] not in allowed
            ):
                continue
            if not re.fullmatch(r"[A-Za-z_]\w*", collection["name"]):
                raise ContentError("Collection names must be identifiers")
            path = (self.root / collection["path"]).resolve()
            if not path.is_relative_to(self.root):
                raise ContentError("Collection path escapes repository")
            revision = subprocess.run(
                ["git", "-C", str(path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
            if revision != collection.get("revision"):
                raise ContentError(
                    "External collection revision must be pinned to its checkout SHA"
                )
            files = sorted([*path.rglob("*.yar"), *path.rglob("*.yara")])
            if any(not file.resolve().is_relative_to(path) for file in files):
                raise ContentError("Collection symlink escapes checkout")
            sources[collection["name"]] = "\n".join(file.read_text() for file in files)
        return sources

    def check(self, group="default", goodware=None):
        rules = self.selected(group)
        if not rules:
            raise ContentError("No eligible signatures for this group")
        source = self.materialize(rules)
        external = self.collections(group)
        compiled = yara.compile(sources={"internal": source, **external})
        positives = 0
        for rule in rules:
            samples = rule.get("references", {}).get("public", {}).get("samples", [])
            if "match_all_referenced_samples" in rule.get(
                "testing_strategy", []
            ) or self.policy.get("require_samples", False):
                if not samples:
                    raise ContentError(f"Missing sample references: {rule['name']}")
                for digest in samples:
                    if not re.fullmatch("[a-f0-9]{64}", digest):
                        raise ContentError("Samples require SHA-256 hashes")
                    if not self.corpus:
                        raise ContentError("Configure the sample corpus")
                    path = self.corpus / digest
                    if (
                        not path.is_file()
                        or sha256(path.read_bytes()).hexdigest() != digest
                    ):
                        raise ContentError(f"Missing or corrupt sample: {digest}")
                    if not any(
                        hit.namespace == "internal" and hit.rule == self.name(rule)
                        for hit in compiled.match(filepath=str(path), timeout=15)
                    ):
                        raise ContentError(f"Sample regression: {rule['name']}")
                    positives += 1
        negatives = 0
        if goodware:
            for path in Path(goodware).rglob("*"):
                if path.is_file():
                    if compiled.match(filepath=str(path), timeout=15):
                        raise ContentError(f"Goodware false positive: {path.name}")
                    negatives += 1
        if self.policy.get("require_goodware", False) and not negatives:
            raise ContentError("A nonempty goodware corpus is required")
        return {
            "valid": True,
            "rules": len(rules),
            "positive_samples": positives,
            "goodware_samples": negatives,
            "source_digest": self.digest(),
        }

    def build(self, output, group="default", kind="sigpack", goodware=None):
        destination = Path(output) / str(uuid4())
        destination.mkdir(parents=True)
        if group not in self.groups:
            raise ContentError("Unknown policy group")
        report = {}
        if kind == "sigpack":
            report = self.check(group, goodware)
            rules = self.selected(group)
            (destination / "signatures.yar").write_text(self.materialize(rules))
            for name, source in self.collections(group).items():
                (destination / f"collection_{name}.yar").write_text(source)
            ids = {rule["id"] for rule in rules}
            (destination / "pairings.yaml").write_text(
                yaml.safe_dump(
                    [pair for pair in self.pairings if set(pair["rule_ids"]) <= ids]
                )
            )
        elif kind == "feedpack":
            if (self.root / "intelligence/pipeline.yaml").exists():
                from .intelligence import assess_repository

                assessment = assess_repository(self.root)
                atomic(destination / "assessment.json", assessment)
                indicators = assessment["released"]
            else:
                indicators = load(self.root / "indicators.yaml", []) or []
            selected = []
            for item in indicators:
                if group not in item.get("groups", ["default"]):
                    continue
                from .intelligence import normalize

                try:
                    item = {**item, "value": normalize(item["type"], item["value"])}
                except (ValueError, TypeError, KeyError, UnicodeError) as error:
                    raise ContentError(f"Invalid indicator: {error}") from error
                if item.get("status", "released") == "released":
                    selected.append(item)
            (destination / "indicators.json").write_text(json.dumps(selected, indent=2))
            report = {
                "valid": True,
                "indicators": len(selected),
                "source_digest": self.digest(),
            }
        elif kind == "codepack":
            components = load(self.root / "components.yaml", []) or []
            for item in components:
                path = (self.root / item["path"]).resolve()
                if not path.is_relative_to(self.root) or not path.is_file():
                    raise ContentError("Component path escapes content repository")
                if sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                    raise ContentError("Component checksum mismatch")
                target = destination / "components" / path.name
                target.parent.mkdir(exist_ok=True)
                target.write_bytes(path.read_bytes())
            report = {
                "valid": True,
                "components": len(components),
                "source_digest": self.digest(),
            }
        else:
            raise ContentError("Unknown pack type")
        git = subprocess.run(
            ["git", "-C", str(self.root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
        )
        manifest = {
            **report,
            "id": destination.name,
            "kind": kind,
            "group": group,
            "git_commit": git.stdout.strip() if git.returncode == 0 else None,
            "collections": [
                {
                    key: item.get(key)
                    for key in ("name", "revision", "severity", "confidence")
                }
                for item in (load(self.root / "collections.yaml", []) or [])
                if item.get("enabled")
                and item.get("name") in self.groups[group].get("collections", [])
            ],
            "files": {
                str(path.relative_to(destination)): sha256(
                    path.read_bytes()
                ).hexdigest()
                for path in destination.rglob("*")
                if path.is_file()
            },
        }
        atomic(destination / "manifest.json", manifest)
        with zipfile.ZipFile(
            destination.with_suffix(".zip"), "w", zipfile.ZIP_DEFLATED
        ) as archive:
            for path in destination.rglob("*"):
                if path.is_file():
                    archive.write(path, path.relative_to(destination))
        return manifest

    def review_valid(self, manifest, review=None):
        review = (
            (load(self.root / "review.yaml", {}) or {}) if review is None else review
        )
        if (
            review.get("source_digest") != manifest["source_digest"]
            or not review.get("reviewer")
            or review.get("reviewer") == review.get("author")
        ):
            raise ContentError(
                "An independent review bound to this content digest is required"
            )
        key = "github_reviewers" if review.get("provider") == "github" else "reviewers"
        allowed = self.groups[manifest["group"]].get(key, [])
        if allowed and str(review["reviewer"]) not in map(str, allowed):
            raise ContentError("Reviewer is not allowed for this group")
        return review

    def publish_testing(self, manifest, channels, now=None, *, review=None):
        review = self.review_valid(manifest, review)
        if manifest.get("source_digest") != self.digest():
            raise ContentError(
                "Build source differs from the current reviewed checkout"
            )
        if not manifest.get("valid"):
            raise ContentError("Validation must pass before release")
        now = now or utcnow()
        base = Path(channels) / manifest["kind"] / manifest["group"]
        state = {
            "manifest": manifest,
            "review": review,
            "published_at": now.isoformat(),
            "telemetry": {},
            "status": "testing",
            "promotion_policy": {
                key: self.policy.get(key, default)
                for key, default in (
                    ("promotion_wait_minutes", 30),
                    ("required_consumers", ["local"]),
                    ("max_detection_rate", 1000),
                )
            },
        }
        with lock(base):
            atomic(base / "testing.json", state)
        atomic(Path(channels) / "history" / f"{manifest['id']}-testing.json", state)
        return state

    def telemetry(self, channels, kind, group, release_id, consumer, report, now=None):
        now = now or utcnow()
        base = Path(channels) / kind / group
        with lock(base):
            state = json.loads((base / "testing.json").read_text())
            if state["manifest"]["id"] != release_id:
                raise ContentError("Telemetry belongs to a different release")
            if (
                not isinstance(report.get("detections"), int)
                or report["detections"] < 0
                or not isinstance(report.get("errors"), int)
                or report["errors"] < 0
            ):
                raise ContentError("Telemetry counts must be nonnegative integers")
            try:
                start, end = (
                    datetime.fromisoformat(report[key])
                    for key in ("window_start", "window_end")
                )
                if (
                    start.tzinfo is None
                    or end.tzinfo is None
                    or start >= end
                    or end > now
                ):
                    raise ValueError()
            except KeyError, TypeError, ValueError:
                raise ContentError(
                    "Telemetry requires an elapsed, timezone-aware observation window"
                )
            state["telemetry"][consumer] = report
            atomic(base / "testing.json", state)
        return state

    def promote(self, channels, kind, group, now=None):
        now = now or utcnow()
        base = Path(channels) / kind / group
        identity = json.loads((base / "testing.json").read_text())["manifest"]["id"]
        try:
            return self._promote(channels, kind, group, now)
        except ContentError as error:
            base = Path(channels) / kind / group
            with lock(base):
                state = json.loads((base / "testing.json").read_text())
                previous = state.get("promotion_block", {})
                if state["manifest"]["id"] == identity and previous.get(
                    "message"
                ) != str(error):
                    state["promotion_block"] = {
                        "message": str(error),
                        "since": now.isoformat(),
                        "alarm": str(error)
                        == "Telemetry alarm blocks production promotion",
                    }
                    atomic(base / "testing.json", state)
            raise

    def _promote(self, channels, kind, group, now):
        base = Path(channels) / kind / group
        with lock(base):
            state = json.loads((base / "testing.json").read_text())
            production = base / "production.json"
            if production.exists():
                existing = json.loads(production.read_text())
                if existing["manifest"]["id"] == state["manifest"]["id"]:
                    return existing
            policy = state.get("promotion_policy", self.policy)
            minutes = policy.get("promotion_wait_minutes", 30)
            published = datetime.fromisoformat(state["published_at"])
            if now < published + timedelta(minutes=minutes):
                raise ContentError("Testing observation window is still open")
            for consumer in policy.get("required_consumers", ["local"]):
                report = state["telemetry"].get(consumer)
                if not report:
                    raise ContentError(f"Missing telemetry from {consumer}")
                start, end = map(
                    datetime.fromisoformat,
                    (report["window_start"], report["window_end"]),
                )
                if (
                    start > published
                    or end > now
                    or end < published + timedelta(minutes=minutes)
                    or now - end > timedelta(minutes=20)
                ):
                    raise ContentError(
                        "Telemetry does not cover a recent observation window"
                    )
                duration = max(1, (end - start).total_seconds() / 60)
                if (
                    report["errors"]
                    or report.get("alarms")
                    or report["detections"] / duration
                    > policy.get("max_detection_rate", 1000)
                ):
                    raise ContentError("Telemetry alarm blocks production promotion")
            self.review_valid(state["manifest"])
            state.pop("promotion_block", None)
            atomic(base / "testing.json", state)
            state.update(status="production", promoted_at=now.isoformat())
            atomic(base / "production.json", state)
            atomic(
                Path(channels)
                / "history"
                / f"{state['manifest']['id']}-production.json",
                state,
            )
            return state
