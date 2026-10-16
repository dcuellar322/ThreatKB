"""Best-effort catalog preparation, isolated from the serving process."""

import fcntl
from hashlib import sha256
import os
from pathlib import Path
import subprocess
import sys
import threading


_guard = threading.Lock()


def start_catalog_prewarm(flask_app):
    """Start once per web process without waiting for source loading or a broker."""
    if os.getenv("THREATKB_ROLE", "web") != "web" or os.getenv("RUN_AGENT", "0") == "1":
        return None
    if flask_app.testing or os.getenv(
        "THREATKB_CATALOG_PREWARM", "1"
    ).strip().lower() in (
        "0",
        "false",
        "no",
        "off",
    ):
        return None
    with _guard:
        existing = flask_app.extensions.get("catalog_prewarm")
        if existing is not None:
            return existing
        environment = dict(os.environ)
        environment["THREATKB_INSTANCE_PATH"] = flask_app.instance_path
        # Preserve instance/config overrides when invoked through a WSGI server.
        for key in ("CONTENT_REPOSITORY", "CONTENT_CORPUS"):
            if flask_app.config.get(key):
                environment[key] = str(flask_app.config[key])
        try:
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "flask",
                    "--app",
                    "app",
                    "warm-content-catalog",
                    "--startup",
                ],
                cwd=Path(flask_app.root_path).parent,
                env=environment,
                stdin=subprocess.DEVNULL,
            )
        except OSError:
            flask_app.logger.warning(
                "Could not start catalog prewarm; source reads remain available.",
                exc_info=True,
            )
            return None
        flask_app.extensions["catalog_prewarm"] = process
        flask_app.logger.info(
            "Catalog prewarm started in background (PID %s).", process.pid
        )

    def reap():
        code = process.wait()
        if code:
            flask_app.logger.warning(
                "Catalog prewarm exited with status %s; source reads remain available.",
                code,
            )
        else:
            flask_app.logger.info("Catalog prewarm finished.")

    threading.Thread(target=reap, name="catalog-prewarm-reaper", daemon=True).start()
    return process


def warm_startup_catalog():
    """Coordinate concurrent web startups without holding the web's catalog lock."""
    from app import app
    from app.routes.content import content_root, repository

    root = content_root()
    # Startup warming is read-only: first-use bootstrap remains a foreground action.
    if not (root / ".git").exists():
        return "Catalog prewarm skipped: repository not initialized."
    directory = Path(app.instance_path) / "content-catalogs"
    if directory.resolve().is_relative_to(root):
        return "Catalog prewarm skipped: cache storage overlaps content."
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory.chmod(0o700)
    path = directory / (sha256(str(root).encode()).hexdigest() + ".startup.lock")
    with open(
        path, "a", opener=lambda name, flags: os.open(name, flags, 0o600)
    ) as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return (
                "Catalog prewarm skipped: another startup is warming this repository."
            )
        try:
            repo = repository(catalog=True)
            return f"Catalog ready: {len(repo.rules)} signatures."
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)
