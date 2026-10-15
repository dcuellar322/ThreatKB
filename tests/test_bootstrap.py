from pathlib import Path
import os
import subprocess


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
