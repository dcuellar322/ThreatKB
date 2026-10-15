from app import app, auto, db, current_user, request, Response
import traceback
import re
from app.models.errors import Error


@app.errorhandler(401)
def handle_401(err):
    return Response("", 401)


@app.errorhandler(409)
def handle_409(err):
    return str(err.description), 409


@app.errorhandler(500)
def handle_500(error):
    app.logger.error("500 error message '%s'" % (error))
    return str(error), 500


@app.errorhandler(Exception)
def handle_exception(exception):
    app.logger.exception(exception)
    if hasattr(exception, "code") and exception.code == 412:
        return exception.description, exception.code

    if hasattr(exception, "code") and str(exception.code).startswith("4"):
        return exception.description, exception.code

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


@app.route('/ThreatKB/error', methods=["GET"])
@auto.doc()
def do_error():
    """Generate a fake HTTP 500 error"""
    return "Generic 500 error", 500


@app.route("/ThreatKB/exception", methods=["GET"])
@auto.doc()
def do_exception():
    """Generate a fake exception"""
    raise Exception("Generic 500 exception")
