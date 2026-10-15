"""Versioned command/container adapters for sample preprocessing."""
import os
from pathlib import Path
import shlex
import subprocess


def run_postprocessor(command, filename, workspace, timeout=120, image=None):
    workspace = Path(workspace).resolve()
    if image:
        if ':' not in image and '@sha256:' not in image:
            raise ValueError('Configure an explicit DFI image version or digest.')
        argv = ['docker', 'run', '--rm', '--network=none', '--mount',
                f'type=bind,source={workspace},target=/work', '--workdir', '/work', image,
                f'/work/{Path(filename).name}']
    else:
        argv = [part.replace('{FILENAME}', str(workspace / filename)).replace('{WORKDIR}', str(workspace))
                for part in shlex.split(command)]
    if not argv:
        raise ValueError('Postprocessor command is empty.')
    result = subprocess.run(argv, cwd=workspace, capture_output=True, text=True,
                            timeout=min(600, max(1, float(timeout))), env=os.environ.copy())
    if result.returncode:
        raise RuntimeError(f'Postprocessor exited {result.returncode}: {result.stderr[-2000:]}')
    return result.stdout, result.stderr, result.returncode
