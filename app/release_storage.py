import os
from pathlib import Path
from app import app
from app.models.cfg_settings import Cfg_settings


def release_workspace():
    root = Path(
        os.getenv("RELEASE_DATA_PATH")
        or Cfg_settings.get_setting("RELEASE_DATA_PATH")
        or Path(app.instance_path) / "releases"
    )
    root.mkdir(parents=True, exist_ok=True)
    return root.resolve()
