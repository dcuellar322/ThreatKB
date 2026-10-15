from pathlib import Path
import os
import subprocess


def test_entrypoint_stops_when_migration_fails(tmp_path):
    command = tmp_path / "flask"
    command.write_text("#!/bin/sh\nexit 17\n")
    command.chmod(0o755)
    result = subprocess.run(["/bin/sh", "docker-entrypoint.sh"],
                            env={**os.environ, "PATH": str(tmp_path), "RUN_AGENT": "0"},
                            capture_output=True)
    assert result.returncode == 17
