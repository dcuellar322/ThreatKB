from app import app, db, admin_only, auto, ENTITY_MAPPING
from app.models import cfg_settings, files
from flask import abort, jsonify, request, send_file, json, Response
from app.authorization import require_artifact, related_visibility
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
import os
import errno
import tempfile
import uuid
import shutil
import hashlib
import re
import magic
from sqlalchemy import or_, and_


def file_hashes(path):
    """Calculate all required hashes in one bounded-memory read."""
    hashes = [hashlib.sha1(), hashlib.md5(), hashlib.sha256()]
    with open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            for digest in hashes:
                digest.update(chunk)
    return tuple(digest.hexdigest() for digest in hashes)


@app.get("/ThreatKB/files")
@login_required
def get_all_files():
    entity_type = request.args.get("entity_type", type=int)
    entity_id = request.args.get("entity_id", type=int)
    if entity_type is not None or entity_id is not None:
        require_artifact(entity_type, entity_id)
    query = files.Files.query.filter_by(entity_type=entity_type, entity_id=entity_id)
    if entity_type is None and not current_user.admin:
        query = query.filter_by(user_id=current_user.id)
    return jsonify([entity.to_dict() for entity in query.order_by(files.Files.id)])


@app.route("/ThreatKB/file_upload", methods=["POST"])
@auto.doc()
@login_required
def upload_file():
    """Upload and create a file
    From Data: file (multi-part file), entity_type (int) {"SIGNATURE": 1, "DNS": 2, "IP": 3, "TASK": 4}, entity_id (int)
    Return: file status dictionary"""
    if "file" not in request.files:
        return jsonify({})

    f = request.files["file"]

    if f.filename == "":
        return jsonify({})

    entity_type = request.values.get("entity_type", type=int)
    entity_id = request.values.get("entity_id", type=int)
    if entity_type is not None or entity_id is not None:
        from app.models.yara_rule import Yara_rule
        from app.models.c2ip import C2ip
        from app.models.c2dns import C2dns
        from app.models.tasks import Tasks

        models = {1: Yara_rule, 2: C2dns, 3: C2ip, 4: Tasks}
        if entity_type not in models or not entity_id or entity_id < 1:
            abort(400, description="Choose a valid artifact for this file.")
        artifact = db.get_or_404(models[entity_type], entity_id)
        if not current_user.admin and artifact.owner_user_id != current_user.id:
            abort(403)
    elif request.values.get("entity_type") or request.values.get("entity_id"):
        abort(400, description="Artifact identifiers must be integers.")
    files_added = {}
    files_skipped = {}
    if f:
        file_store_path_root = (
            cfg_settings.Cfg_settings.get_setting("FILE_STORE_PATH") or "/tmp"
        )
        filename = secure_filename(f.filename)
        if not filename:
            abort(400, description="Choose a filename containing letters or numbers.")
        folder = os.path.join(file_store_path_root, str(entity_type), str(entity_id))
        os.makedirs(folder, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            prefix=".upload-", dir=folder, delete=False
        ) as incoming:
            full_path = incoming.name
        f.save(full_path)
        sha1, md5, sha256 = file_hashes(full_path)

        new_directory = os.path.join(
            file_store_path_root,
            str(entity_type) if entity_type is not None else "None",
            str(entity_id) if entity_id is not None else "None",
            sha1,
        )

        os.makedirs(new_directory, exist_ok=True)
        shutil.move(full_path, os.path.join(new_directory, filename))
        full_path = os.path.join(new_directory, filename)

        files_added["UPLOADED"] = [filename]

        file_entity = files.Files.query.filter_by(
            entity_type=entity_type, entity_id=entity_id, sha1=sha1, filename=filename
        ).first()

        if not file_entity:
            file_entity = files.Files(
                filename=f.filename,
                content_type=f.content_type,
                entity_type=entity_type,
                entity_id=entity_id,
                user_id=current_user.id,
                sha1=sha1,
                md5=md5,
                sha256=sha256,
            )
            db.session.add(file_entity)
        else:
            file_entity.user_id = current_user.id
            file_entity.date_modified = db.func.current_timestamp()
            file_entity.md5 = md5
            file_entity.sha1 = sha1
            file_entity.sha256 = sha256

        parent_file = file_entity

        ## POSTPROCESSOR FUNCTIONALITY ##
        app.logger.debug("POSTPROCESSOR STARTING")
        postprocessors = cfg_settings.Cfg_settings.get_settings("POSTPROCESSOR%") or []
        from app.compat import strtobool
        from app.postprocessing import select_postprocessors, is_dfi_processor

        dfi_enabled = strtobool(
            os.getenv("POSTPROCESSOR_DFI_ENABLED")
            or cfg_settings.Cfg_settings.get_setting("POSTPROCESSOR_DFI_ENABLED")
            or False
        )
        postprocessors, postprocessing_skipped = select_postprocessors(
            postprocessors, dfi_enabled
        )
        postprocessing_exclude_files_regex = cfg_settings.Cfg_settings.get_setting(
            "POSTPROCESSING_EXCLUDE_FILES_REGEX"
        )
        for postprocessor in postprocessors:
            app.logger.debug("POSTPROCESSOR STARTING '%s'" % (postprocessor.key))
            postprocessing_tempdir = (
                cfg_settings.Cfg_settings.get_setting("POSTPROCESSING_FILE_STORE_PATH")
                or "/tmp"
            )
            tempdir = "%s/%s" % (postprocessing_tempdir.rstrip(os.sep), uuid.uuid4())
            files_added[postprocessor.key] = []
            files_skipped[postprocessor.key] = []
            try:
                os.makedirs(tempdir)
                shutil.copy(full_path, tempdir)
            except OSError:
                shutil.rmtree(tempdir, ignore_errors=True)
                raise

            current_path = os.getcwd()
            app.logger.debug("POSTPROCESSOR CWD is now '%s'" % (tempdir))
            app.logger.debug("POSTPROCESSOR DIRLIST is:\n\n%s" % (os.listdir(tempdir)))
            try:
                from app.postprocessing import run_postprocessor

                image = (
                    cfg_settings.Cfg_settings.get_setting("POSTPROCESSOR_DFI_IMAGE")
                    if is_dfi_processor(postprocessor)
                    else None
                )
                timeout = (
                    cfg_settings.Cfg_settings.get_setting("POSTPROCESSOR_TIMEOUT")
                    or 120
                )
                stdout, stderr, return_code = run_postprocessor(
                    postprocessor.value, filename, tempdir, timeout, image
                )
                app.logger.debug("POSTPROCESSOR STDOUT is:\n\n%s" % (stdout))
                app.logger.debug("POSTPROCESSOR STDERR is: \n\n%s" % (stderr))
                app.logger.debug("POSTPROCESSOR RETCODE is: \n\n%s" % (return_code))
            except Exception as e:
                shutil.rmtree(tempdir, ignore_errors=True)
                abort(422, description=f"Postprocessor {postprocessor.key} failed: {e}")

            app.logger.debug(
                "POSTPROCESSOR DIRLIST is now:\n\n%s" % (os.listdir(tempdir))
            )
            for root, dirs, files_local in os.walk(tempdir, topdown=False):
                for name in files_local:
                    current_tempfile = os.path.join(root, name)
                    if os.path.islink(current_tempfile) or not os.path.isfile(
                        current_tempfile
                    ):
                        continue
                    sha1, md5, sha256 = file_hashes(current_tempfile)
                    path = root.replace(tempdir, "").lstrip(os.path.sep)

                    app.logger.debug("POSTPROCESSOR TEMPFILE '%s'" % (current_tempfile))
                    app.logger.debug(
                        f"POSTPROCESSOR FILES: {root} {dirs} {files_local}"
                    )
                    try:
                        if name == filename:
                            app.logger.debug(
                                "Filename '%s' is the original file. Skipping." % (name)
                            )
                            continue
                        if re.search(
                            postprocessing_exclude_files_regex, name, re.IGNORECASE
                        ):
                            app.logger.debug(
                                "Filename '%s' matched against postprocessing exclude regex of '%s'. Skipping."
                                % (filename, postprocessing_exclude_files_regex)
                            )
                            files_skipped[postprocessor.key].append(name)
                            continue
                    except:
                        pass

                    full_path_temp = os.path.join(
                        file_store_path_root,
                        request.values["entity_type"]
                        if "entity_type" in request.values
                        else "",
                        str(entity_id) if entity_id is not None else "None",
                        parent_file.sha1,
                        path,
                        name,
                    )

                    if not os.path.exists(os.path.dirname(full_path_temp)):
                        try:
                            os.makedirs(os.path.dirname(full_path_temp))
                        except OSError as exc:  # Guard against race condition
                            if exc.errno != errno.EEXIST:
                                raise

                    shutil.move(current_tempfile, full_path_temp)
                    file_entity = files.Files.query.filter_by(
                        entity_type=entity_type,
                        entity_id=entity_id,
                        sha1=sha1,
                        parent_sha1=parent_file.sha1,
                        filename=name,
                    ).first()
                    app.logger.debug("POSTPROCESSOR FILE ENTITY '%s'" % (file_entity))
                    mime = magic.Magic(mime=True)
                    if not file_entity:
                        file_entity = files.Files(
                            filename=name,
                            content_type=mime.from_file(full_path_temp),
                            entity_type=entity_type,
                            entity_id=entity_id,
                            user_id=current_user.id,
                            sha1=sha1,
                            md5=md5,
                            sha256=sha256,
                            parent_sha256=parent_file.sha256,
                            parent_sha1=parent_file.sha1,
                            parent_md5=parent_file.md5,
                            path=path,
                        )
                        db.session.add(file_entity)
                        app.logger.debug(
                            "POSTPROCESSOR FILE ADDED '%s'" % (file_entity.filename)
                        )
                        files_added[postprocessor.key].append(name)
                    else:
                        file_entity.user_id = current_user.id
                        file_entity.content_type = mime.from_file(full_path_temp)
                        file_entity.date_modified = db.func.current_timestamp()
                        file_entity.sha1 = sha1
                        file_entity.sha256 = sha256
                        file_entity.md5 = md5
                        file_entity.path = path
                        file_entity.parent_sha256 = parent_file.sha256
                        file_entity.parent_sha1 = parent_file.sha1
                        file_entity.parent_md5 = parent_file.md5

            shutil.rmtree(tempdir)

        db.session.commit()
        return jsonify(
            {
                "files_added": files_added,
                "files_skipped": files_skipped,
                "postprocessing_skipped": postprocessing_skipped,
            }
        )

    return jsonify({})


@app.route(
    "/ThreatKB/files/<string:entity_type>/<int:entity_id>/<int:file_id>",
    methods=["GET"],
)
@auto.doc()
@login_required
def get_file_for_entity(entity_type, entity_id, file_id):
    """Return file associated with file_id, entity_id, and entity_type
    Return: file (streamed for downloading)"""
    file_entity = db.session.get(files.Files, file_id)

    if not file_entity:
        abort(404)

    require_file_access(file_entity)
    if (
        str(file_entity.entity_type) != entity_type
        or file_entity.entity_id != entity_id
    ):
        abort(404)
    full_path = os.path.join(
        file_entity.full_path, secure_filename(file_entity.filename)
    )
    if not os.path.exists(full_path):
        abort(404)

    return send_file(
        full_path, download_name="{}".format(file_entity.filename), as_attachment=True
    )


@app.route("/ThreatKB/files/<int:file_id>", methods=["DELETE"])
@auto.doc()
@login_required
@admin_only()
def delete_file(file_id):
    """Delete file associated with given file_id
    Return: None"""
    entity = db.session.get(files.Files, file_id)
    if not entity:
        abort(404)

    if request.args.get("path", False) and request.args.get("path") == "1":
        related = files.Files.query.filter_by(
            entity_type=entity.entity_type, entity_id=entity.entity_id
        )
        if entity.is_parent_file:
            related.filter(files.Files.parent_sha1 == entity.sha1).delete(
                synchronize_session=False
            )
        else:
            # Match complete directory components, never sibling prefix names.
            prefix = (entity.path or "").rstrip(os.sep)
            related.filter(files.Files.parent_sha1 == entity.parent_sha1).filter(
                or_(
                    files.Files.path == prefix,
                    files.Files.path.startswith(prefix + os.sep, autoescape=True),
                )
            ).filter(files.Files.id != entity.id).delete(synchronize_session=False)
        db.session.delete(entity)
        db.session.commit()

        if os.path.exists(entity.full_path):
            shutil.rmtree(entity.full_path)

        return "", 204

    else:
        full_path = os.path.join(entity.full_path, secure_filename(entity.filename))
        if os.path.exists(full_path):
            os.remove(full_path)

        db.session.delete(entity)
        db.session.commit()
        return "", 204


def require_file_access(entity):
    if entity.entity_type is None:
        if not current_user.admin and entity.user_id != current_user.id:
            abort(403)
    else:
        require_artifact(entity.entity_type, entity.entity_id)


@app.get("/ThreatKB/files/<int:file_id>")
@login_required
def download_file(file_id):
    entity = db.get_or_404(files.Files, file_id)
    require_file_access(entity)
    path = os.path.join(entity.full_path, secure_filename(entity.filename))
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, download_name=entity.filename, as_attachment=True)
