from app import app, db, auto, ENTITY_MAPPING
from app.models.yara_rule import Yara_rule_history, Yara_rule
from app.models.cfg_states import Cfg_states
from app.routes import test_yara_rule
from app.models import yara_rule, cfg_states, comments
from flask import abort, jsonify, request, Response, json
from flask_login import current_user, login_required
from app.compat import strtobool
from app.utilities import extract_yara_rules_text, extract_artifacts_text
from app.models.metadata import Metadata, MetadataMapping
from app.models.releases import get_release_yara_rule_history_mapping, get_release_metadata
from app.routes.batch import batch_update, batch_delete
from app.routes.bookmarks import is_bookmarked, delete_bookmarks
from app.routes.cfg_category_range_mapping import update_cfg_category_range_mapping_current
from app.routes.tags_mapping import create_tags_mapping, delete_tags_mapping, get_tags_for_source, \
    batch_delete_tags_mapping_for_source_id
from app.routes.comments import create_comment
from app.models.cfg_settings import Cfg_settings
from app.utilities import filter_entities
import datetime
import uuid
import random
import string
import base64


@app.post('/ThreatKB/yara_rules/<int:id>/restore')
@login_required
def restore_yara_rule(id):
    entity = db.get_or_404(Yara_rule, id)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)
    from app.detection import validate_signature
    try:
        validate_signature({key: getattr(entity, key) for key in ("name", "strings", "condition", "imports")}, entity.id)
    except Exception as error:
        abort(422, description=f"Repair this signature before restoring it: {error}")
    entity.active = True
    entity.modified_user_id = current_user.id
    db.session.commit()
    return jsonify(entity.to_dict(short=True))


@app.post('/ThreatKB/yara_rules/<int:id>/revisions/<int:revision>/restore')
@login_required
def restore_signature_revision(id, revision):
    entity = db.get_or_404(Yara_rule, id)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)
    snapshot = Yara_rule_history.query.filter_by(yara_rule_id=id, revision=revision).first_or_404()
    import json
    data = json.loads(snapshot.rule_json)
    data['owner_user_id'] = entity.owner_user_id
    data.pop('owner_user', None)
    data['active'] = entity.active
    data['new_comment'] = f'Restored signature content from revision {revision}.'
    from app.signature_service import save_signature
    restored, changed = save_signature(data, entity)
    return jsonify(restored.to_dict(include_yara_rule_string=True))


@app.route('/ThreatKB/yara_rules/merge_signatures', methods=['POST'])
def merge_signatures():
    signatures = request.json.get('signatures', [])
    save_output = request.json.get('save_output', 0)
    signature_ids = request.json.get('signature_ids', [])

    for i in range(len(signatures)):
        try:
            signatures[i] = base64.b64decode(signatures[i]).decode()
        except:
            pass

    if signature_ids and (not current_user.is_authenticated or not current_user.active or not current_user.admin):
        abort(403)

    for id_ in signature_ids:
        signature = db.session.query(yara_rule.Yara_rule).filter(yara_rule.Yara_rule.id == id_).first()
        if signature:
            signatures.append(signature.to_dict(include_yara_rule_string=True)['yara_rule_string'])

    if not signatures or not type(signatures) == list or len(signatures) < 2:
        abort(412, description="You must provide at least 2 signatures as a list")

    rules = extract_yara_rules_text("\n\n".join(signatures))
    rule_name = f"Merged_Rule_{str(uuid.uuid4())[:8]}"
    description = f"\"Merger of {', '.join([rule['parsed_rule']['rule_name'] for rule in rules])}\""
    strings = ""
    condition = ""
    imports = ""
    r = 1
    for rule in rules:
        old_new = {}
        current_strings = []
        postfix = f"r{r}"
        for s in rule['parsed_rule']['strings']:
            old_name = s['name'].strip()
            if old_name.startswith('$'):
                name = f"${s['name'].strip()[1:]}_{postfix}"
            else:
                name = f"{s['name'].strip()}_{postfix}"

            if s['value'].startswith("{") or s['value'].startswith("/"):
                value = s['value'].strip()
            else:
                value = f"\"{s['value'].strip()}\""

            old_new[old_name] = name
            modifier = ' '.join(s.get('modifiers', []))
            current_strings.append(
                f"{name} = {value} {modifier}"
            )
        strings += '\n\t\t' + '\n\t\t'.join(current_strings)
        app.logger.info(f"condition is\n{rule['condition']}")
        this_condition = rule['condition'].strip()
        for old, new in old_new.items():
            this_condition = this_condition.replace(old, new)
        condition += f"(\n\t{this_condition}\n\t)\n\tor\n\t"
        imports += rule['imports'] + "\n" if not rule['imports'] in imports else ""
        r += 1

    condition = condition.rstrip("\n\tor\n\t")
    full_rule = f"""
    {imports}

    rule {rule_name}
    {{
        meta:
            description = {description}
        strings:{strings}
        condition:
            {condition}
    }}
    """

    app.logger.info(f"rule is\n{full_rule}")
    if not save_output:
        return jsonify({"merged_signature": full_rule.strip(" ").strip()})
    else:
        if not current_user.is_authenticated or not current_user.active or not current_user.admin:
            abort(403)
        output = extract_artifacts_text(do_extract_ip=False,
                                        do_extract_dns=False,
                                        do_extract_signature=True,
                                        text=full_rule)
        rule_dict = output[0]
        yr, fta = yara_rule.Yara_rule.get_yara_rule_from_yara_dict(rule_dict, {})
        yr.created_user_id, yr.modified_user_id = current_user.id, current_user.id
        staging_state = db.session.query(Cfg_states).filter(Cfg_states.is_staging_state > 0).first()
        yr.state = staging_state.state
        yr.description = description.strip('"')
        yr.revision = 1
        db.session.add(yr)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            raise
        return jsonify(yr.to_dict()), 201


@app.route('/ThreatKB/yara_rules/merge_signatures_by_id', methods=['POST'])
@auto.doc()
@login_required
def merge_signatures_by_id():
    """Merge a signature into another
    From Data: merge_from_id (int), merge_to_id (int)
    Return: merged yara_rule artifact dictionary"""
    merge_from_id = request.json.get("merge_from_id", None)
    merge_to_id = request.json.get("merge_to_id", None)

    if not merge_from_id or not merge_to_id:
        abort(412, description="Not enough info provided")

    merge_from_yr = yara_rule.Yara_rule.query.filter_by(id=merge_from_id).first()
    merge_to_yr = yara_rule.Yara_rule.query.filter_by(id=merge_to_id).first()

    merged_state = "Merged"
    if not cfg_states.Cfg_states.query.filter_by(state=merged_state).first():
        db.session.add(cfg_states.Cfg_states(state=merged_state))
        try:
            db.session.commit()
        except:
            db.session.rollback()
            raise

    merge_from_yr.state = merged_state
    db.session.add(merge_from_yr)
    merged_into_comment = "This yara rule was merged into signature '%s' with event id '%s' by '%s'" % (
        merge_to_yr.name, merge_to_yr.eventid, current_user.email)
    db.session.add(
        comments.Comments(comment=merged_into_comment, entity_type=ENTITY_MAPPING["SIGNATURE"],
                          entity_id=merge_from_yr.id, user_id=current_user.id))

    merged_from_comment = "The yara rule '%s' with event id '%s' was merged into this yara rule by '%s'" % (
        merge_from_yr.name, merge_from_yr.eventid, current_user.email)
    db.session.add(
        comments.Comments(comment=merged_from_comment, entity_type=ENTITY_MAPPING["SIGNATURE"],
                          entity_id=merge_to_yr.id, user_id=current_user.id))
    try:
        db.session.commit()
    except:
        db.session.rollback()
        raise

    delete_bookmarks(ENTITY_MAPPING["SIGNATURE"], merge_from_id, current_user.id)

    return get_yara_rule(merge_to_yr.id)


@app.route('/ThreatKB/yara_rules', methods=['GET'])
@auto.doc()
@login_required
def get_all_yara_rules():
    """Return a list of all yara_rule artifacts.

    include_merged: variable controlling whether merged signatures are returned, default False
    include_inactive: variable controlling whether inactive signatures are returned, default False

    Pagination variables:
    page_number: page number to start on, default 0
    page_size: the size of each page, default None (dont paginate)
    sort_by: column to sort by, must exist on the Yara_rule model, default None
    sort_direction: the direction to sort by if sorting, default ASC
    searches: dictionary of column filters as {column1:filter1, column2:filter2}, columns must exist on Yara_rule model, default {}

    Return: list of yara_rule artifact dictionaries"""

    view = request.args.get("view", "Active Only")

    if view == "All":
        include_inactive = True
        include_active = True
    elif view == "Active Only":
        include_inactive = False
        include_active = True
    elif view == "Inactive Only":
        include_inactive = True
        include_active = False
    else:
        include_inactive = False
        include_active = True

    include_yara_string = bool(strtobool(request.args.get("include_yara_string", "False")))
    short = bool(strtobool(request.args.get("short", "true")))
    include_metadata = bool(strtobool(request.args.get('include_metadata', "true")))
    include_tags = bool(strtobool(request.args.get('include_tags', "true")))
    include_comments = bool(strtobool(request.args.get('include_comments', "true")))

    if include_yara_string:
        include_yara_string = True

    include_merged = request.args.get('include_merged', False)
    searches = request.args.get('searches', '{}')
    page_number = request.args.get('page_number', False)
    page_size = request.args.get('page_size', False)
    sort_by = request.args.get('sort_by', False)
    operator = request.args.get('operator', 'and')
    sort_direction = request.args.get('sort_dir', 'ASC')
    exclude_totals = request.args.get('exclude_totals', False)

    response_dict = filter_entities(entity=yara_rule.Yara_rule,
                                    artifact_type=ENTITY_MAPPING["SIGNATURE"],
                                    searches=searches,
                                    page_number=page_number,
                                    page_size=page_size,
                                    sort_by=sort_by,
                                    sort_direction=sort_direction,
                                    include_metadata=include_metadata,
                                    exclude_totals=exclude_totals,
                                    default_sort="creation_date",
                                    include_inactive=include_inactive,
                                    include_tags=include_tags,
                                    include_comments=include_comments,
                                    include_active=include_active,
                                    include_merged=include_merged,
                                    include_yara_string=include_yara_string,
                                    short=short,
                                    operator=operator)

    return Response(response_dict, mimetype='application/json')


@app.route('/ThreatKB/yara_rules/<int:id>', methods=['GET'])
@auto.doc()
@login_required
def get_yara_rule(id):
    """Return yara_rule artifact associated with the given id
    Return: yara_rule artifact dictionary"""
    include_yara_string = request.args.get("include_yara_string", False)
    include_revisions = strtobool(request.args.get("include_revisions", "true"))
    include_metadata = request.args.get("include_metadata", True)
    short = strtobool(request.args.get("short", "false"))

    if include_yara_string:
        include_yara_string = True

    entity = db.session.get(yara_rule.Yara_rule, id)
    if not entity:
        abort(404)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)

    return_dict = entity.to_dict(include_yara_rule_string=include_yara_string, short=short,
                                 include_revisions=include_revisions, include_metadata=include_metadata)
    return_dict["bookmarked"] = True if is_bookmarked(ENTITY_MAPPING["SIGNATURE"], id, current_user.id) \
        else False

    return jsonify(return_dict)


@app.route('/ThreatKB/yara_rules/<int:id>/release_mapping', methods=['GET'])
@auto.doc()
@login_required
def get_yara_rule_release_mapping(id):
    """Return yara_rule artifact associated with the given id
    Return: yara_rule artifact dictionary"""

    entity = db.session.get(yara_rule.Yara_rule, id)
    if not entity:
        abort(404)
    if not current_user.admin and entity.owner_user_id != current_user.id:
        abort(403)

    rule_history = db.session.query(Yara_rule_history.id).filter(Yara_rule_history.yara_rule_id == entity.id).all()
    if not rule_history:
        return jsonify([])

    release_mapping = get_release_yara_rule_history_mapping()
    release_metadata = get_release_metadata()
    mapping = {}
    for rh in rule_history:
        if not rh.id in mapping:
            mapping[rh.id] = []
        if rh.id in release_mapping:
            for release_id in release_mapping[rh.id]:
                mapping[rh.id].append(release_metadata[release_id])

    return_mapping = {}
    for key, val in mapping.items():
        return_mapping[int(key)] = ",".join([release["name"] for release in val])
    return jsonify(return_mapping)


@app.route('/ThreatKB/yara_rules/<int:yara_rule_id>/revision/<int:revision>', methods=['GET'])
@auto.doc()
@login_required
def get_yara_rule_string_from_revision(yara_rule_id, revision):
    """Return yara_rule string associated with the given yara rule and revision number
    Return: yara_rule string representation"""

    current_entity = db.session.get(yara_rule.Yara_rule, yara_rule_id)
    revision_entity = Yara_rule_history.query \
        .filter_by(yara_rule_id=yara_rule_id) \
        .filter_by(revision=revision) \
        .first()

    if not current_entity or not revision_entity:
        abort(404)

    if not current_user.admin and current_entity.owner_user_id != current_user.id:
        abort(403)

    revision_dict = revision_entity.to_dict()
    yara_revision_dict = revision_dict["rule_json"]
    yara_rule_string = Yara_rule.to_yara_rule_string(yara_revision_dict)

    return jsonify(yara_rule_string)


@app.route('/ThreatKB/yara_rules', methods=['POST', 'PUT'])
@auto.doc()
@login_required
def create_yara_rule():
    """Create yara_rule artifact
    From Data: name (str), state(str), category (str), condition (str), strings (str)
    Return: yara_rule artifact dictionary"""
    from app.signature_service import save_signature
    entity, changed = save_signature(request.get_json())
    return jsonify(entity.to_dict(include_yara_rule_string=True)), 201

@app.route('/ThreatKB/yara_rules/<int:id>', methods=['PUT'])
@auto.doc()
@login_required
def update_yara_rule(id):
    """Update yara_rule artifact
    From Data: name (str), state(str), category (str), condition (str), strings (str)
    Return: yara_rule artifact dictionary"""
    from app.signature_service import save_signature
    entity = db.get_or_404(Yara_rule, id)
    entity, changed = save_signature(request.get_json(), entity)
    return jsonify(entity.to_dict(include_yara_rule_string=True)), 200


@app.route('/ThreatKB/yara_rules/batch/edit', methods=['PUT'])
@auto.doc()
@login_required
def batch_update_yara_rules():
    """Batch update yara rules artifacts
    From Data: batch {
                 state (str),
                 owner_user (str),
                 tags (array),
                 ids (array)
               }
    Return: Success Code"""

    if 'batch' in request.json and request.json['batch']:
        return batch_update(batch=request.json['batch'],
                            artifact=yara_rule.Yara_rule,
                            session=db.session)


@app.route('/ThreatKB/yara_rules/<int:id>', methods=['DELETE'])
@auto.doc()
@login_required
def delete_yara_rule(id):
    """INACTIVATE yara_rule artifact associated with id
    Return: None"""
    entity = db.session.get(yara_rule.Yara_rule, id)

    if entity.active:
        entity.active = False

        if not entity:
            abort(404)

        if not current_user.admin and entity.owner_user_id != current_user.id:
            abort(403)

        db.session.merge(entity)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            raise

        # delete_tags_mapping(entity.__tablename__, entity.id)
        delete_bookmarks(ENTITY_MAPPING["SIGNATURE"], id, current_user.id)
    else:

        db.session.query(yara_rule.Yara_testing_history).filter(
            yara_rule.Yara_testing_history.yara_rule_id.in_([entity.id])).delete(synchronize_session='fetch')
        db.session.query(yara_rule.Yara_rule_history).filter(
            yara_rule.Yara_rule_history.yara_rule_id.in_([entity.id])).delete(synchronize_session='fetch')
        db.session.delete(entity)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            raise

        delete_bookmarks(ENTITY_MAPPING["SIGNATURE"], id, current_user.id)

    return jsonify(''), 204


@app.route('/ThreatKB/yara_rules/batch/delete', methods=['PUT'])
@auto.doc()
@login_required
def batch_delete_yara_rules():
    """Batch inactivate yara rules artifacts
    From Data: batch {
                 ids (array)
               }
    Return: Success Code"""

    if 'batch' in request.json and request.json['batch']:
        return batch_delete(batch=request.json['batch'],
                            artifact=yara_rule.Yara_rule,
                            session=db.session,
                            entity_mapping=ENTITY_MAPPING["SIGNATURE"],
                            is_yara=True)


@app.route('/ThreatKB/yara_rules/copy', methods=['POST'])
@auto.doc()
@login_required
def copy_yara_rules():
    """Get yara strings for copy
    From Data: ids (array)
    Return: yara strings for copy"""

    signatures = []
    if 'copy' in request.json and request.json['copy'] \
            and 'ids' in request.json['copy'] and request.json['copy']['ids']:
        for sig_id in request.json['copy']['ids']:
            sig = db.session.get(yara_rule.Yara_rule, sig_id)
            if not sig:
                abort(404)
            if not current_user.admin and sig.owner_user_id != current_user.id:
                abort(403)

            signatures.append(sig.to_dict(include_yara_rule_string=True)["yara_rule_string"])

    return jsonify('\n\n'.join(map(str, signatures))), 200


@app.route('/ThreatKB/yara_rules/delete_all_inactive', methods=['PUT'])
@auto.doc()
@login_required
def delete_all_inactive_yara_rules():
    rules_to_delete = db.session.query(yara_rule.Yara_rule).filter(yara_rule.Yara_rule.active == 0).all()
    rules_to_delete_ids = [rule.id for rule in rules_to_delete]
    db.session.query(yara_rule.Yara_testing_history).filter(
        yara_rule.Yara_testing_history.yara_rule_id.in_(rules_to_delete_ids)).delete(synchronize_session='fetch')
    db.session.query(yara_rule.Yara_rule_history).filter(
        yara_rule.Yara_rule_history.yara_rule_id.in_(rules_to_delete_ids)).delete(synchronize_session='fetch')
    db.session.query(yara_rule.Yara_rule).filter(yara_rule.Yara_rule.active == 0).delete()
    try:
        db.session.commit()
    except:
        db.session.rollback()
        raise
    return jsonify(''), 200
