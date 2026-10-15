from pathlib import Path
from uuid import uuid4
import json
import click
import yaml
from .engine import Repository, load


@click.group()
@click.option("--root", type=click.Path(path_type=Path), default=Path("detections"))
@click.pass_context
def cli(ctx, root):
    ctx.obj = root


@cli.command("ids")
@click.pass_obj
def ids(root):
    for path in (root / "rules").glob("*.yaml"):
        rule = load(path)
        if rule.get("id") in (None, "AUTO"):
            rule["id"] = str(uuid4())
            path.write_text(yaml.safe_dump(rule, sort_keys=False))


@cli.command("check")
@click.option("--group", default="default")
@click.option("--corpus", type=click.Path(path_type=Path))
@click.option("--goodware", type=click.Path(path_type=Path))
@click.pass_obj
def check(root, group, corpus, goodware):
    click.echo(json.dumps(Repository(root, corpus).check(group, goodware)))


@cli.command("build")
@click.option("--group", default="default")
@click.option(
    "--kind", type=click.Choice(["sigpack", "feedpack", "codepack"]), default="sigpack"
)
@click.option("--corpus", type=click.Path(path_type=Path))
@click.option("--goodware", type=click.Path(path_type=Path))
@click.option(
    "--output", type=click.Path(path_type=Path), default=Path("instance/builds")
)
@click.pass_obj
def build(root, group, kind, corpus, goodware, output):
    click.echo(
        json.dumps(
            Repository(root, corpus, load_rules=kind == "sigpack").build(
                output, group, kind, goodware
            )
        )
    )


@cli.command("publish-testing")
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--channels", type=click.Path(path_type=Path), default=Path("instance/channels")
)
@click.pass_obj
def publish_testing(root, manifest, channels):
    value = json.loads(manifest.read_text())
    click.echo(
        json.dumps(
            Repository(root, load_rules=value["kind"] == "sigpack").publish_testing(
                value, channels
            )
        )
    )


@cli.command("telemetry")
@click.argument("release_id")
@click.argument("consumer")
@click.argument("report", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--kind", type=click.Choice(["sigpack", "feedpack", "codepack"]), default="sigpack"
)
@click.option("--group", default="default")
@click.option(
    "--channels", type=click.Path(path_type=Path), default=Path("instance/channels")
)
@click.pass_obj
def telemetry(root, release_id, consumer, report, kind, group, channels):
    click.echo(
        json.dumps(
            Repository(root, load_rules=kind == "sigpack").telemetry(
                channels,
                kind,
                group,
                release_id,
                consumer,
                json.loads(report.read_text()),
            )
        )
    )


@cli.command("promote")
@click.option(
    "--kind", type=click.Choice(["sigpack", "feedpack", "codepack"]), default="sigpack"
)
@click.option("--group", default="default")
@click.option(
    "--channels", type=click.Path(path_type=Path), default=Path("instance/channels")
)
@click.pass_obj
def promote(root, kind, group, channels):
    click.echo(
        json.dumps(
            Repository(root, load_rules=kind == "sigpack").promote(
                channels, kind, group
            )
        )
    )


if __name__ == "__main__":
    cli()
