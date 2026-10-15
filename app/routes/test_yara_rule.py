import multiprocessing
import ntpath
import os
import time
import datetime
import io
import yara
import re
import uuid
import subprocess

from sqlalchemy import func, not_, text
from sqlalchemy.ext.serializer import loads, dumps

from app import app, db, admin_only, auto
from app.celeryapp import celery
from app.models import yara_rule
from flask import abort, jsonify, request, json, Response
from flask_login import current_user, login_required

from app.models.users import KBUser
from app.models.cfg_settings import Cfg_settings
from app.models.yara_rule import (
    Yara_testing_history,
    Yara_rule,
    Yara_testing_history_files_matches,
)


@app.route("/ThreatKB/tests", methods=["GET"])
@auto.doc()
@login_required
def get_all_tests():
    """Return a list of all tests artifacts.

    Pagination variables:
    page_number: page number to start on, default 0
    page_size: the size of each page, default None (dont paginate)
    sort_by: column to sort by, must exist on the Yara_rule model, default None
    sort_direction: the direction to sort by if sorting, default ASC
    searches: dictionary of column filters as {column1:filter1, column2:filter2}, columns must exist on Yara_rule model, default {}

    Return: list of tests artifact dictionaries
    """
    from app.querying import apply_sort
    from sqlalchemy.orm import selectinload

    try:
        searches = json.loads(request.args.get("searches", "{}"))
        size = int(request.args.get("page_size", 25))
        page = int(request.args.get("page_number", 0))
        if (
            not isinstance(searches, dict)
            or len(searches) > 32
            or not 1 <= size <= 200
            or page < 0
        ):
            raise ValueError()
    except (TypeError, ValueError):
        abort(400, description="Choose valid test filters and page size 1–200.")
    query = Yara_testing_history.query
    if not current_user.admin:
        query = query.filter(
            Yara_testing_history.yara_rule.has(owner_user_id=current_user.id)
        )
    for key, value in searches.items():
        if value is None or value == "":
            continue
        if key == "yara_rule_name":
            query = query.filter(
                Yara_testing_history.yara_rule.has(
                    Yara_rule.name.contains(str(value), autoescape=True)
                )
            )
        elif key == "user_email":
            query = query.filter(
                Yara_testing_history.user.has(
                    KBUser.email.contains(str(value), autoescape=True)
                )
            )
        elif key in ("id", "yara_rule_id", "revision", "status", "test_type"):
            query = query.filter(getattr(Yara_testing_history, key) == value)
        else:
            abort(400, description="Choose a supported test filter.")
    total = query.count()
    query = apply_sort(
        query,
        Yara_testing_history,
        request.args.get("sort_by") or "start_time",
        request.args.get("sort_dir", "DESC"),
    )
    rows = (
        query.options(
            selectinload(Yara_testing_history.user),
            selectinload(Yara_testing_history.yara_rule).load_only(Yara_rule.name),
        )
        .offset(page * size)
        .limit(size)
        .all()
    )
    return jsonify(data=[row.to_dict() for row in rows], total_count=total)


@app.route("/ThreatKB/tests/create/<int:rule_id>", methods=["POST"])
@auto.doc()
@login_required
def test_yara_rule_rest(rule_id):
    """Synchronously test yara rule associated with rule_id against all files attached to it
    Return: results dictionary"""
    yara_rule_entity = db.session.get(yara_rule.Yara_rule, rule_id)
    if not yara_rule_entity:
        abort(404)
    if not current_user.admin and yara_rule_entity.owner_user_id != current_user.id:
        abort(403)

    try:
        files_to_test = []
        is_neg_test = str(request.args.get("negative", "0"))
        is_neg_test = True if is_neg_test == "1" else False
        if not is_neg_test:
            for f in yara_rule_entity.files:
                file_store_path = Cfg_settings.get_setting("FILE_STORE_PATH")
                if not file_store_path:
                    raise Exception("FILE_STORE_PATH configuration setting not set.")
                print(f"path is {f.id} {f.filename} {f.full_path}")
                files_to_test.append(os.path.join(f.full_path, f.filename))
                # files_to_test.append(os.path.join(file_store_path,
                #                                  str(f.entity_type) if f.entity_type is not None else "",
                #                                  str(f.entity_id) if f.entity_id is not None else "",
                #                                  str(f.filename)))
        if not is_neg_test:
            return jsonify(
                test_yara_rule(
                    yara_rule_entity, files_to_test, current_user.id, False, is_neg_test
                )
            ), 200
        else:
            from app.routes.jobs import enqueue_job

            job = enqueue_job(
                "test_rule",
                {"rule_id": yara_rule_entity.id, "negative": True},
                current_user.id,
            )
            return jsonify(job.to_dict()), 202
    except Exception as e:
        return str(e), 422


@app.route("/ThreatKB/tests/<int:test_id>", methods=["GET"])
@auto.doc()
@login_required
def get_test_results(test_id):
    yrh = db.get_or_404(Yara_testing_history, test_id)
    if not current_user.admin and yrh.yara_rule.owner_user_id != current_user.id:
        abort(403)
    return jsonify(yrh.to_dict(include_results=True)), 200


@celery.task()
def test_yara_rule_task(rule_id, user, is_neg_test):
    print("in test_yara_rule_task")
    files_to_test = []
    yara_rule_entity = db.session.get(yara_rule.Yara_rule, rule_id)
    if not yara_rule_entity:
        abort(500)

    print("yara rule entity %s" % (yara_rule_entity))
    neg_test_dir = Cfg_settings.get_setting("NEGATIVE_TESTING_FILE_DIRECTORY")
    if not os.path.exists(neg_test_dir):
        abort(500)

    for root_path, dirs, dir_files in os.walk(neg_test_dir):
        for f_name in dir_files:
            files_to_test.append(os.path.join(root_path, f_name))

    print("files to test %s" % (str(files_to_test)))
    return test_yara_rule(yara_rule_entity, files_to_test, user, True, is_neg_test)


def test_yara_rule(
    yara_rule_entity, files_to_test, user, is_async=False, is_neg_test=False
):
    from pathlib import Path
    from hashlib import file_digest
    from app.detection import validate_signature

    if isinstance(yara_rule_entity, int):
        yara_rule_entity = db.get_or_404(Yara_rule, yara_rule_entity)
    values = {
        key: getattr(yara_rule_entity, key)
        for key in ("name", "strings", "condition", "imports")
    }
    compiled = validate_signature(values, yara_rule_entity.id)
    started = time.monotonic()
    history = Yara_testing_history(
        yara_rule_id=yara_rule_entity.id,
        revision=yara_rule_entity.revision,
        start_time=datetime.datetime.now(),
        files_tested=0,
        files_matched=0,
        avg_millis_per_file=0,
        total_files=len(files_to_test),
        status="RUNNING",
        test_type="NEGATIVE" if is_neg_test else "POSITIVE",
        user_id=user,
    )
    db.session.add(history)
    db.session.flush()
    matched, errors = 0, []
    timeout = min(
        60, max(1, int(Cfg_settings.get_setting("SCAN_TIMEOUT_SECONDS") or 15))
    )
    for index, file_path in enumerate(files_to_test):
        before = time.monotonic()
        digest, hit, error = None, False, ""
        try:
            with open(file_path, "rb") as sample:
                digest = file_digest(sample, "sha256").hexdigest()
            hits = compiled.match(filepath=str(file_path), timeout=timeout)
            hit = any(item.rule == yara_rule_entity.name for item in hits)
        except (OSError, yara.Error) as exception:
            error = str(exception)
            errors.append(f"{Path(file_path).name}: {error}")
        elapsed = time.monotonic() - before
        matched += int(hit)
        db.session.add(
            Yara_testing_history_files_matches(
                history_id=history.id,
                path=str(file_path),
                sha256=digest,
                matched=hit,
                run_time=elapsed,
                stdout=yara_rule_entity.name if hit else "",
                stderr=error[:2000],
                command="yara-python",
                command_match_test_regex="",
            )
        )
        history.files_tested = index + 1
        history.files_matched = matched
        if (index + 1) % 25 == 0:
            db.session.commit()
    duration = (time.monotonic() - started) * 1000
    history.end_time = datetime.datetime.now()
    history.avg_millis_per_file = duration / len(files_to_test) if files_to_test else 0
    history.status = "ERROR" if errors else "COMPLETE"
    db.session.commit()
    return dict(
        history_id=history.id,
        duration=duration,
        files_tested=len(files_to_test),
        files_matched=matched,
        tests_terminated=0,
        errors_encountered=len(errors),
        error_msgs=errors,
        passed=bool(files_to_test)
        and not errors
        and (matched == 0 if is_neg_test else matched == len(files_to_test)),
    )


def does_rule_compile(yara_dict):
    from app.detection import validate_signature

    try:
        validate_signature(yara_dict, yara_dict.get("id"))
        return True, 0, "", ""
    except (yara.Error, ValueError) as error:
        return False, 1, "", str(error)


def get_yara_rule(yara_rule_entity):
    rule_string = yara_rule_entity.to_dict(
        include_yara_rule_string=True, include_relationships=False
    )["yara_rule_string"]
    # rule_string = """
    # rule %s
    # {
    #     strings:
    #         %s
    #     condition:
    #         %s
    # }
    # """ % (yara_rule_entity.name,
    #        yara_rule_entity.strings,
    #        yara_rule_entity.condition)

    return rule_string


def perform_rule_match(rule, file_path, manager_dict, yara_command, yara_test_regex):
    start = time.time()
    rule_temp_path = "/tmp/%s.yar" % (str(uuid.uuid4()).replace("-", ""))
    with open(rule_temp_path, "w") as f:
        f.write(rule)

    command = yara_command.replace("RULE", rule_temp_path).replace(
        "FILE_PATH", file_path
    )
    proc = subprocess.Popen(
        command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    proc.wait()
    stdout, stderr = proc.communicate()
    end = time.time()
    manager_dict["duration"] = end - start
    manager_dict["stdout"] = stdout.decode()
    manager_dict["stderr"] = stderr.decode()
    manager_dict["file_path"] = file_path
    manager_dict["command"] = yara_command
    manager_dict["command_match_test_regex"] = yara_test_regex

    if re.search(yara_test_regex, manager_dict["stdout"]):
        manager_dict["match"] = True
    else:
        manager_dict["match"] = False
    return manager_dict


def get_all_sig_ids():
    sig_ids = []
    yara_rules = yara_rule.Yara_rule.query.all()
    for rule in yara_rules:
        sig_ids.append(rule.id)

    return sig_ids


if __name__ == "__main__":
    import sys

    rule = """rule hello {
        strings:
                $a1="hello"
        condition:
                any of them
}"""
    a = perform_rule_match(
        rule,
        "/Users/danny/Desktop/temp/hello.yar",
        multiprocessing.Manager().dict(),
        "/usr/local/bin/yara RULE FILE_PATH",
        "[A-Za-z0-9]",
    )
    sys.stdout.write(str(a))


@app.get("/ThreatKB/yara_rules/<int:rule_id>/sample-results")
@login_required
def sample_result_comparison(rule_id):
    rule = db.get_or_404(Yara_rule, rule_id)
    if not current_user.admin and rule.owner_user_id != current_user.id:
        abort(403)
    test_type = request.args.get("test_type", "POSITIVE").upper()
    if test_type not in ("POSITIVE", "NEGATIVE"):
        abort(400)
    histories = (
        Yara_testing_history.query.filter_by(yara_rule_id=rule_id, test_type=test_type)
        .order_by(Yara_testing_history.id.desc())
        .all()
    )
    if not histories:
        return jsonify(files=[], current_history_id=None)
    latest = histories[0].id
    rows = (
        db.session.query(Yara_testing_history_files_matches)
        .join(Yara_testing_history)
        .filter(
            Yara_testing_history.yara_rule_id == rule_id,
            Yara_testing_history.test_type == test_type,
        )
        .order_by(Yara_testing_history_files_matches.history_id)
        .all()
    )
    results = {}
    for result in rows:
        item = results.setdefault(
            result.path,
            dict(
                path=result.path, ever_matched=False, matched=None, sha256=result.sha256
            ),
        )
        item["ever_matched"] |= result.matched
        if result.history_id == latest:
            item["matched"] = result.matched
            item["sha256"] = result.sha256
            item["error"] = result.stderr
    show_all = request.args.get("show_all", "false").lower() == "true"
    output = []
    for item in results.values():
        item["status"] = (
            "not_tested"
            if item["matched"] is None
            else "matched"
            if item["matched"]
            else "regressed"
            if item["ever_matched"]
            else "never_matched"
        )
        if show_all or item["ever_matched"]:
            output.append(item)
    return jsonify(files=output, current_history_id=latest)
