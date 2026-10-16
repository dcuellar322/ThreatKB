import fcntl
from hashlib import sha256
import importlib
from pathlib import Path
import subprocess
import sys
import threading
from unittest.mock import Mock

from flask import Flask

from app import app
from app.catalog_startup import start_catalog_prewarm, warm_startup_catalog

startup = importlib.import_module("app.catalog_startup")
routes = importlib.import_module("app.routes.content")


def test_startup_spawns_once_and_does_not_wait_for_child(tmp_path, monkeypatch):
    web = Flask("startup", instance_path=str(tmp_path / "instance"))
    web.config["CONTENT_REPOSITORY"] = str(tmp_path / "source")
    child = Mock(pid=123)
    finished = threading.Event()
    release = threading.Event()

    def wait():
        release.wait(5)
        finished.set()
        return 0

    child.wait.side_effect = wait
    spawn = Mock(return_value=child)
    monkeypatch.setattr(startup.subprocess, "Popen", spawn)
    monkeypatch.delenv("THREATKB_CATALOG_PREWARM", raising=False)
    web.add_url_rule("/ready", view_func=lambda: "ready")
    try:
        assert start_catalog_prewarm(web) is child
        assert not finished.is_set()
        assert start_catalog_prewarm(web) is child
        spawn.assert_called_once()
        args, kwargs = spawn.call_args
        assert args[0] == [
            sys.executable,
            "-m",
            "flask",
            "--app",
            "app",
            "warm-content-catalog",
            "--startup",
        ]
        assert kwargs["env"]["THREATKB_INSTANCE_PATH"] == web.instance_path
        assert kwargs["env"]["CONTENT_REPOSITORY"] == web.config["CONTENT_REPOSITORY"]
        assert kwargs["stdin"] == subprocess.DEVNULL
        with web.test_client() as client:
            assert client.get("/ready").status_code == 200
            assert not finished.is_set()
    finally:
        release.set()
        assert finished.wait(5)


def test_testing_and_opt_out_do_not_spawn(tmp_path, monkeypatch):
    web = Flask("startup", instance_path=str(tmp_path / "instance"))
    spawn = Mock()
    monkeypatch.setattr(startup.subprocess, "Popen", spawn)
    web.testing = True
    assert start_catalog_prewarm(web) is None
    web.testing = False
    monkeypatch.setenv("THREATKB_CATALOG_PREWARM", "0")
    assert start_catalog_prewarm(web) is None
    spawn.assert_not_called()


def test_spawn_failure_does_not_break_web_startup(tmp_path, monkeypatch, caplog):
    web = Flask("startup", instance_path=str(tmp_path / "instance"))
    monkeypatch.delenv("THREATKB_CATALOG_PREWARM", raising=False)
    monkeypatch.setattr(
        startup.subprocess, "Popen", Mock(side_effect=OSError("Unavailable executable"))
    )
    assert start_catalog_prewarm(web) is None
    assert "source reads remain available" in caplog.text


def test_startup_cli_builds_cache_without_content_changes(
    client, monkeypatch, tmp_path
):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    routes.repository()
    (root / "rules").mkdir()
    (root / "rules/fixture.yaml").write_text(
        'id: 75b62257-b23c-4089-9506-3ef05af9aefe\nname: StartupFixture\ncategory: UC\nstrings: ""\ncondition: "false"\n'
    )
    head = routes.git("rev-parse", "HEAD")
    status = routes.git("status", "--porcelain")
    result = app.test_cli_runner().invoke(args=["warm-content-catalog", "--startup"])
    assert result.exit_code == 0, result.output
    assert "Catalog ready: 1 signatures." in result.output
    assert list((Path(app.instance_path) / "content-catalogs").glob("*.sqlite3"))
    assert routes.git("rev-parse", "HEAD") == head
    assert routes.git("status", "--porcelain") == status
    assert client.get("/health").status_code == 200


def test_other_startup_holds_lock_without_waiting(client, monkeypatch, tmp_path):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    routes.repository()
    folder = Path(app.instance_path) / "content-catalogs"
    folder.mkdir()
    path = folder / (sha256(str(root).encode()).hexdigest() + ".startup.lock")
    with path.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        monkeypatch.setattr(
            routes,
            "repository",
            Mock(side_effect=AssertionError("Must skip duplicate work")),
        )
        assert "another startup" in warm_startup_catalog()


def test_uninitialized_or_overlapping_source_is_not_modified(
    client, monkeypatch, tmp_path
):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    assert "not initialized" in warm_startup_catalog()
    assert not root.exists()
    root = Path(app.instance_path)
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    (root / ".git").mkdir()
    assert "overlaps content" in warm_startup_catalog()
    assert not (root / "content-catalogs").exists()


def test_failed_warm_releases_lock_and_web_remains_available(
    client, monkeypatch, tmp_path
):
    root = tmp_path / "source"
    monkeypatch.setitem(app.config, "CONTENT_REPOSITORY", str(root))
    routes.repository()
    (root / "rules").mkdir()
    target = root / "rules/broken.yaml"
    target.write_text("name: [broken")
    result = app.test_cli_runner().invoke(args=["warm-content-catalog", "--startup"])
    assert result.exit_code == 1
    assert "Catalog prewarm failed" in result.output
    assert client.get("/health").status_code == 200
    target.unlink()
    retried = app.test_cli_runner().invoke(args=["warm-content-catalog", "--startup"])
    assert retried.exit_code == 0, retried.output
    assert "Catalog ready: 0 signatures." in retried.output


def test_worker_and_scheduler_roles_do_not_launch_web_warming(tmp_path, monkeypatch):
    web = Flask("startup", instance_path=str(tmp_path / "instance"))
    spawn = Mock()
    monkeypatch.setattr(startup.subprocess, "Popen", spawn)
    for role in ("worker", "scheduler"):
        monkeypatch.setenv("THREATKB_ROLE", role)
        assert start_catalog_prewarm(web) is None
    monkeypatch.setenv("THREATKB_ROLE", "web")
    monkeypatch.setenv("RUN_AGENT", "1")
    assert start_catalog_prewarm(web) is None
    spawn.assert_not_called()
