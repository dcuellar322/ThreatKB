from app import app, db, admin_only, auto, current_user
from app.models import cfg_states
from flask import abort, jsonify, request, Response
from flask_login import login_required
from sqlalchemy import or_
import json


@app.route('/ThreatKB/cfg_states', methods=['GET'])
@auto.doc()
@login_required
def get_all_cfg_states():
    """Return all config states
    Return: list of config state dictionaries"""
    entities = cfg_states.Cfg_states.query
    if not current_user.admin:
        entities = entities.filter_by(is_release_state=0)

    from app.models.yara_rule import Yara_rule
    from app.models.c2ip import C2ip
    from app.models.c2dns import C2dns
    from app.models.tasks import Tasks
    from app.querying import visible_query
    counts={}
    for key,model,kind in [('sig_count',Yara_rule,1),('dns_count',C2dns,2),('ip_count',C2ip,3),('task_count',Tasks,4)]:
        counts[key]=dict(visible_query(model,kind).filter(model.active.is_(True)).with_entities(model.state,db.func.count(model.id)).group_by(model.state).all())
    return jsonify([dict(id=entity.id,state=entity.state,is_release_state=entity.is_release_state,is_staging_state=entity.is_staging_state,is_retired_state=entity.is_retired_state,**{key:values.get(entity.state,0) for key,values in counts.items()}) for entity in entities.all()])


@app.route('/ThreatKB/cfg_states/<int:id>', methods=['GET'])
@auto.doc()
@login_required
@admin_only()
def get_cfg_states(id):
    """Return config state associated with given id
    Return: config state dictionary"""
    entity = db.session.get(cfg_states.Cfg_states, id)
    if not entity:
        abort(404)

    if not current_user.admin and entity.is_release_state:
        abort(403)
    return jsonify(entity.to_dict())


@app.route('/ThreatKB/cfg_states', methods=['POST', 'PUT'])
@auto.doc()
@login_required
@admin_only()
def create_cfg_states():
    """Create config state
    From Data: state (str), is_release_state (bool)
    Return: config state dictionary
    """
    entity = cfg_states.Cfg_states(
        state=request.json['state'],
        is_release_state=0 if not request.json.get("is_release_state", None) else 1,
        is_staging_state=0 if not request.json.get("is_staging_state", None) else 1,
        is_retired_state=0 if not request.json.get("is_retired_state", None) else 1
    )

    if (entity.is_staging_state + entity.is_retired_state + entity.is_release_state) > 1:
        raise Exception("You cannot have a single state as draft, release, or retired state.")

    if entity.is_release_state:
        cfg_states.Cfg_states.query.filter(
            cfg_states.Cfg_states.is_release_state > 0).update(
            {cfg_states.Cfg_states.is_release_state: 0})
    elif entity.is_retired_state:
        cfg_states.Cfg_states.query.filter(
            cfg_states.Cfg_states.is_retired_state > 0).update(
            {cfg_states.Cfg_states.is_retired_state: 0})
    elif entity.is_staging_state:
        cfg_states.Cfg_states.query.filter(
            cfg_states.Cfg_states.is_staging_state > 0).update(
            {cfg_states.Cfg_states.is_staging_state: 0})

    db.session.add(entity)
    db.session.commit()
    return jsonify(entity.to_dict()), 201


@app.route('/ThreatKB/cfg_states/<int:id>', methods=['PUT'])
@auto.doc()
@login_required
@admin_only()
def update_cfg_states(id):
    """Update config state associated with the given id
    From Data: state (str), is_release_state (bool)
    Return: config setting dictionary"""
    entity = db.session.get(cfg_states.Cfg_states, id)
    if not entity:
        abort(404)
    entity = cfg_states.Cfg_states(
        state=request.json['state'],
        id=id,
        is_release_state=0 if not request.json.get("is_release_state", None) else 1,
        is_staging_state=0 if not request.json.get("is_staging_state", None) else 1,
        is_retired_state=0 if not request.json.get("is_retired_state", None) else 1
    )

    if (entity.is_staging_state + entity.is_retired_state + entity.is_release_state) > 1:
        raise Exception("You cannot have a single state as draft, release, or retired state.")

    if entity.is_release_state:
        cfg_states.Cfg_states.query.filter(
            cfg_states.Cfg_states.is_release_state > 0).update(
            {cfg_states.Cfg_states.is_release_state: 0})
    elif entity.is_retired_state:
        cfg_states.Cfg_states.query.filter(
            cfg_states.Cfg_states.is_retired_state > 0).update(
            {cfg_states.Cfg_states.is_retired_state: 0})
    elif entity.is_staging_state:
        cfg_states.Cfg_states.query.filter(
            cfg_states.Cfg_states.is_staging_state > 0).update(
            {cfg_states.Cfg_states.is_staging_state: 0})

    db.session.merge(entity)
    db.session.commit()
    return jsonify(entity.to_dict()), 200


@app.route('/ThreatKB/cfg_states/<int:id>', methods=['DELETE'])
@auto.doc()
@login_required
@admin_only()
def delete_cfg_states(id):
    """Delete config state associated with the given id
    Return: None"""
    entity = db.session.get(cfg_states.Cfg_states, id)
    if not entity:
        abort(404)
    db.session.delete(entity)
    db.session.commit()
    return jsonify(''), 204
