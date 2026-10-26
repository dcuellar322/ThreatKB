from app import app, auto, db, current_user
from flask import request
import traceback
import re
from app.models.errors import Error


from werkzeug.exceptions import HTTPException
from flask import jsonify


@app.errorhandler(HTTPException)
def handle_http_error(error):
    db.session.rollback()
    return jsonify(error=error.description), error.code


@app.errorhandler(Exception)
def handle_exception(exception):
    app.logger.exception(exception)

    db.session.rollback()

    try:
        err = Error(
            stacktrace=traceback.format_exc(),
            user_id=getattr(current_user, "id", None),
            remote_addr=request.remote_addr,
            args=str(request.args.to_dict(flat=False)),
            method=request.method,
            route=str(request.url_rule) if request.url_rule else request.path,
        )
        db.session.add(err)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Could not persist error report")
    from flask import jsonify

    return jsonify(error="An internal error occurred."), 500


@app.route("/ThreatKB/error", methods=["GET"])
@auto.doc()
def do_error():
    """Generate a fake HTTP 500 error"""
    return "Generic 500 error", 500


@app.route("/ThreatKB/exception", methods=["GET"])
@auto.doc()
def do_exception():
    """Generate a fake exception"""
    raise Exception("Generic 500 exception")


from sqlalchemy.exc import IntegrityError, DataError


@app.errorhandler(IntegrityError)
def handle_conflict(error):
    db.session.rollback()
    return jsonify(
        error="This change conflicts with an existing record or a referenced definition."
    ), 409


@app.errorhandler(DataError)
def handle_invalid_database_value(error):
    db.session.rollback()
    return jsonify(
        error="A field has an invalid value or exceeds its allowed length."
    ), 400
