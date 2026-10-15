from pathlib import Path
import os
import subprocess


def test_database_credentials_are_not_interpreted_as_url_syntax():
    from app.database_config import database_url
    from sqlalchemy.engine import make_url

    password = "qa:p@ss/word#with%escapes?"
    result = database_url(
        "sqlite:///:memory:",
        {
            "THREATKB_DATABASE_HOST": "db",
            "THREATKB_DATABASE_USER": "analyst@example.test",
            "THREATKB_DATABASE_PASSWORD": password,
            "THREATKB_DATABASE_URL": "mysql://ignored:ignored@localhost/ignored",
        },
    )
    decoded = make_url(result.render_as_string(hide_password=False))
    assert decoded.password == password
    assert decoded.username == "analyst@example.test"
    assert decoded.host == "db"
    assert decoded.database == "threatkb"
    assert (
        database_url("mysql://u:p@localhost/kb", {})
        == "mysql+pymysql://u:p@localhost/kb"
    )
    assert database_url("sqlite:///:memory:", {}) == "sqlite:///:memory:"


def test_entrypoint_stops_when_migration_fails(tmp_path):
    command = tmp_path / "flask"
    command.write_text("#!/bin/sh\nexit 17\n")
    command.chmod(0o755)
    result = subprocess.run(
        ["/bin/sh", "docker-entrypoint.sh"],
        env={**os.environ, "PATH": str(tmp_path), "RUN_AGENT": "0"},
        capture_output=True,
    )
    assert result.returncode == 17


def test_container_roles_use_explicit_celery_app_and_persistent_scheduler(tmp_path):
    command = tmp_path / "celery"
    command.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
    command.chmod(0o755)
    for role in ("worker", "scheduler"):
        result = subprocess.run(
            ["/bin/sh", "docker-entrypoint.sh"],
            env={
                **os.environ,
                "PATH": str(tmp_path) + os.pathsep + os.defpath,
                "THREATKB_ROLE": role,
                "THREATKB_INSTANCE_PATH": str(tmp_path),
                "RUN_AGENT": "0",
            },
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.startswith("-A\napp.celeryapp:celery\n")
        if role == "scheduler":
            assert f"--schedule={tmp_path}/celerybeat-schedule" in result.stdout
        else:
            assert "worker" in result.stdout
    result = subprocess.run(
        ["/bin/sh", "docker-entrypoint.sh"],
        env={**os.environ, "THREATKB_ROLE": "misspelled", "RUN_AGENT": "0"},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
