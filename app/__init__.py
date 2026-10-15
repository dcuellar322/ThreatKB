import os
import sys
import logging
import datetime
from app.compat import strtobool
import functools

from flask import Flask, abort, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_login import current_user
from flask_migrate import Migrate
from flask import make_response
from functools import wraps, update_wrapper
from flask_caching import Cache
from app.documentation import Autodoc


app = Flask(
    __name__,
    static_url_path="",
    instance_path=os.getenv("THREATKB_INSTANCE_PATH") or None,
)

app.config.update(
    SQLALCHEMY_DATABASE_URI="sqlite:///threatkb.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    LOGGING_LEVEL="INFO",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,
)
if os.path.exists("config.py"):
    app.config.from_object("config")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "THREATKB_DATABASE_URL", app.config["SQLALCHEMY_DATABASE_URI"]
)
if app.config["SQLALCHEMY_DATABASE_URI"].startswith("mysql://"):
    app.config["SQLALCHEMY_DATABASE_URI"] = (
        "mysql+pymysql://" + app.config["SQLALCHEMY_DATABASE_URI"][8:]
    )
app.config["SECRET_KEY"] = os.getenv("THREATKB_SECRET_KEY")
if not app.config["SECRET_KEY"]:
    from pathlib import Path

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)
    key_file = Path(app.instance_path) / "secret-key"
    if not key_file.exists():
        with open(
            key_file, "x", opener=lambda path, flags: os.open(path, flags, 0o600)
        ) as key:
            import secrets

            key.write(secrets.token_hex(32))
    app.config["SECRET_KEY"] = key_file.read_text().strip()

if app.config.get("REDIS_CACHE_URL", None):
    cache = Cache(
        app,
        config={
            "CACHE_TYPE": "RedisCache",
            "CACHE_REDIS_URL": app.config.get("REDIS_CACHE_URL"),
        },
    )
else:
    cache = Cache(app, config={"CACHE_TYPE": "SimpleCache"})


auto = Autodoc(app)

# db = SQLAlchemy(app)
db = SQLAlchemy(app, engine_options={"pool_recycle": 600})
login_manager = LoginManager()
login_manager.init_app(app)
bcrypt = Bcrypt(app)
celery = None
migrate = Migrate(app, db)

ENTITY_MAPPING = {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4, "RELEASE": 5}
ENTITY_MAPPING_URI = {
    1: "yara_rules",
    2: "c2dns",
    3: "c2ips",
    4: "tasks",
    5: "releases",
}
ACTIVITY_TYPE = {
    "ARTIFACT_CREATED": "Artifact Created",
    "ARTIFACT_MODIFIED": "Artifact Modified",
    "COMMENTS": "Comment",
    "STATE_TOGGLED": "State Toggled",
    "RELEASES_MADE": "Release Made",
    "TAG_CREATED": "Tag Created",
    "TAG_REMOVED": "Tag Removed",
}


def nocache(view):
    @wraps(view)
    def no_cache(*args, **kwargs):
        import datetime as datetime

        response = make_response(view(*args, **kwargs))
        response.headers["Last-Modified"] = datetime.datetime.now()
        response.headers["Cache-Control"] = (
            "no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0"
        )
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "-1"
        return response

    return update_wrapper(no_cache, view)


def admin_only():
    def wrapper(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if not current_user.admin:
                return abort(403)
            return f(*args, **kwargs)

        return wrapped

    return wrapper


from app.models import cfg_settings


def set_celery_stuff(flask_app):
    flask_app.config["BROKER_URL"] = os.getenv(
        "REDIS_BROKER_URL", cfg_settings.Cfg_settings.get_setting("REDIS_BROKER_URL")
    )
    flask_app.config["TASK_SERIALIZER"] = os.getenv(
        "REDIS_TASK_SERIALIZER",
        cfg_settings.Cfg_settings.get_setting("REDIS_TASK_SERIALIZER"),
    )
    flask_app.config["RESULT_SERIALIZER"] = os.getenv(
        "REDIS_RESULT_SERIALIZER",
        cfg_settings.Cfg_settings.get_setting("REDIS_RESULT_SERIALIZER"),
    )
    flask_app.config["ACCEPT_CONTENT"] = os.getenv(
        "REDIS_ACCEPT_CONTENT",
        cfg_settings.Cfg_settings.get_setting("REDIS_ACCEPT_CONTENT"),
    )
    flask_app.config["FILE_STORE_PATH"] = os.getenv(
        "FILE_STORE_PATH", cfg_settings.Cfg_settings.get_setting("FILE_STORE_PATH")
    )
    flask_app.config["MAX_MILLIS_PER_FILE_THRESHOLD"] = os.getenv(
        "MAX_MILLIS_PER_FILE_THRESHOLD",
        cfg_settings.Cfg_settings.get_setting("MAX_MILLIS_PER_FILE_THRESHOLD"),
    )

    if flask_app.config["MAX_MILLIS_PER_FILE_THRESHOLD"]:
        flask_app.config["MAX_MILLIS_PER_FILE_THRESHOLD"] = float(
            flask_app.config["MAX_MILLIS_PER_FILE_THRESHOLD"]
        )


set_celery_stuff(app)


from app.celeryapp import celery


# Import route modules for registration without leaking their globals.
from importlib import import_module

for route_module in (
    "version",
    "index",
    "authentication",
    "c2ips",
    "c2dns",
    "cfg_settings",
    "yara_rules",
    "cfg_states",
    "comments",
    "tags",
    "tags_mapping",
    "files",
    "import_",
    "cfg_category_range_mapping",
    "test_yara_rule",
    "error_handling",
    "releases",
    "tasks",
    "documentation",
    "access_keys",
    "whitelist",
    "search",
    "bookmarks",
    "scripts",
    "metadata",
    "errors",
    "activity_log",
    "macros",
    "countries",
):
    import_module("app.routes." + route_module)

from app.models import users
from app.models import c2ip
from app.models import c2dns
from app.models import yara_rule
from app.models import cfg_states
from app.models import comments
from app.models import tags
from app.models import tags_mapping
from app.models import files
from app.models import scripts
from app.models import cfg_category_range_mapping
from app.models import releases
from app.models import tasks
from app.models import access_keys
from app.models import users
from app.models import whitelist
from app.models import bookmarks
from app.models import metadata
from app.models import errors
from app.models import activity_log
from app.models import macros

from app.geo_ip_helper import get_geo_for_ip


# DB functions below used by unit tests.
def connect_db():
    """Connects to the specific database."""
    return db


def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    return connect_db()


def init_db():
    """Initializes the database."""

    def upgrade(revision="head"):
        with app.app_context():
            from flask_migrate import upgrade as _upgrade

            _upgrade(revision=revision)

    upgrade()


def deinit_db():
    """Deinitializes the database."""

    def downgrade(revision="base"):
        with app.app_context():
            from flask_migrate import downgrade as _downgrade

            _downgrade(revision=revision)

    downgrade()


@app.teardown_request
def teardown_request(exception):
    if exception:
        db.session.rollback()
    db.session.remove()


def setup_logging():
    app.logger.setLevel(app.config["LOGGING_LEVEL"])


@login_manager.user_loader
def load_user(userid):
    user = db.session.get(users.KBUser, int(userid))
    return user if user and user.active else None


@login_manager.request_loader
def load_user_from_request(request):
    authorization = request.headers.get("Authorization", "")
    token = (
        authorization[7:]
        if authorization.startswith("Bearer ")
        else request.args.get("token")
    )
    s_key = request.headers.get("X-ThreatKB-Secret") or request.args.get("secret_key")
    if token and s_key:
        from app.routes.access_keys import is_token_active

        valid_token = is_token_active(token)
        if valid_token:
            user = users.KBUser.verify_auth_token(str(token), s_key)
            if user:
                return user
            else:
                abort(401)
        else:
            abort(401)

    return None


def generate_app():
    """Compatibility entry point for existing WSGI and worker launchers."""
    return app


def run(debug=False, port=0, host=""):
    import os

    port = port or int(os.getenv("LISTEN_PORT", 5000))
    host = host or os.getenv("LISTEN_ON", "127.0.0.1")
    debug = debug or strtobool(os.getenv("DEBUG", "false"))

    generate_app()
    app.run(debug=debug, port=port, host=host)


with app.app_context():
    setup_logging()

from app import commands
from app.routes import scanner

from app.routes import scheduled_confidence
from app import dev_seed
from app.routes import jobs

from app.routes import ingestion_health

from app.routes import notifications
from app.routes import dashboard
from app.routes import content

from app.models import indexes
