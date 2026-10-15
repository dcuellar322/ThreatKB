"""Versioned command/container adapters for sample preprocessing."""

import os
from pathlib import Path
import shlex
import subprocess


CONTROL_SETTINGS = {
    "POSTPROCESSOR_TIMEOUT",
    "POSTPROCESSOR_DFI_IMAGE",
    "POSTPROCESSOR_DFI_ENABLED",
}


def is_dfi_processor(setting):
    if "DFI" in setting.key.upper():
        return True
    try:
        command = shlex.split(setting.value or "")
    except ValueError:
        return False
    return bool(command and Path(command[0]).name == "pp-dev")


def select_postprocessors(settings, dfi_enabled=False):
    selected, skipped = [], {}
    for setting in settings:
        if setting.key in CONTROL_SETTINGS:
            continue
        if is_dfi_processor(setting) and not dfi_enabled:
            skipped[setting.key] = "Optional DFI preprocessing is disabled."
        else:
            selected.append(setting)
    return selected, skipped


def run_postprocessor(command, filename, workspace, timeout=120, image=None):
    workspace = Path(workspace).resolve()
    if image:
        if ":" not in image and "@sha256:" not in image:
            raise ValueError("Configure an explicit DFI image version or digest.")
        argv = [
            "docker",
            "run",
            "--rm",
            "--network=none",
            "--mount",
            f"type=bind,source={workspace},target=/work",
            "--workdir",
            "/work",
            image,
            f"/work/{Path(filename).name}",
        ]
    else:
        argv = [
            part.replace("{FILENAME}", str(workspace / filename)).replace(
                "{WORKDIR}", str(workspace)
            )
            for part in shlex.split(command)
        ]
    if not argv:
        raise ValueError("Postprocessor command is empty.")
    result = subprocess.run(
        argv,
        cwd=workspace,
        capture_output=True,
        text=True,
        timeout=min(600, max(1, float(timeout))),
        env=os.environ.copy(),
    )
    if result.returncode:
        raise RuntimeError(
            f"Postprocessor exited {result.returncode}: {result.stderr[-2000:]}"
        )
    return result.stdout, result.stderr, result.returncode
