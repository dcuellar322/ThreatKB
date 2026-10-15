from flask_login import current_user

from app import app, db, admin_only, auto
from app.models import whitelist
from flask import abort, jsonify, request, Response
from flask_login import login_required
import json
import re

@app.route('/ThreatKB/whitelist', methods=['GET'])
@auto.doc()
@login_required
def get_all_whitelist():
    """Return all whitelist
    Return: list of whitelist dictionaries"""
    entities = whitelist.Whitelist.query.all()
    return Response(json.dumps([entity.to_dict() for entity in entities]), mimetype='application/json')


@app.route('/ThreatKB/whitelist/<int:id>', methods=['GET'])
@auto.doc()
@login_required
def get_whitelist(id):
    """Return whitelist associated with given id
    Return: whitelist dictionary"""
    entity = db.session.get(whitelist.Whitelist, id)
    if not entity:
        abort(404)
    return jsonify(entity.to_dict())


@app.route('/ThreatKB/whitelist', methods=['POST', 'PUT'])
@auto.doc()
@login_required
def create_whitelist():
    """Create new whitelist
    From Data: whitelist_artifact(str), notes (str)
    Return: whitelist dictionary"""

    re.compile(request.json['whitelist_artifact'])

    entity = whitelist.Whitelist(
        whitelist_artifact=request.json['whitelist_artifact'],
        notes=request.json['notes'],
        created_by_user_id=current_user.id,
        modified_by_user_id=current_user.id
    )
    db.session.add(entity)
    db.session.commit()

    return jsonify(entity.to_dict()), 201


@app.route('/ThreatKB/whitelist/<int:id>', methods=['PUT'])
@auto.doc()
@login_required
def update_whitelist(id):
    """Update tag associated with given id
    From Data: whitelist_artifact(str), notes (str)
    Return: whitelist dictionary"""
    entity = db.session.get(whitelist.Whitelist, id)
    if not entity:
        abort(404)

    re.compile(request.json['whitelist_artifact'])

    entity = whitelist.Whitelist(
        whitelist_artifact=request.json['whitelist_artifact'],
        notes=request.json['notes'],
        modified_by_user_id=current_user.id,
        id=id
    )
    db.session.merge(entity)
    db.session.commit()

    entity = db.session.get(whitelist.Whitelist, id)
    return jsonify(entity.to_dict()), 200


@app.route('/ThreatKB/whitelist/<int:id>', methods=['DELETE'])
@auto.doc()
@login_required
def delete_whitelist(id):
    """Delete whitelist associated with given id
    Return: None"""
    entity = db.session.get(whitelist.Whitelist, id)
    if not entity:
        abort(404)
    db.session.delete(entity)
    db.session.commit()
    return jsonify(''), 204
from ipaddress import ip_network
import re
import json


@app.post('/ThreatKB/whitelist/import-misp')
@login_required
@admin_only()
def import_misp_warninglist():
    """Import an official MISP warninglist JSON document idempotently."""
    data = request.get_json()
    entries = data.get('list')
    kind = data.get('type')
    if not isinstance(entries, list) or len(entries) > 100000 or kind not in {'hostname', 'string', 'cidr', 'regex'}:
        abort(400, description='Provide a MISP hostname, string, cidr, or regex warninglist.')
    normalized = []
    try:
        for entry in entries:
            if not isinstance(entry, str) or not entry or len(entry) > 1024:
                raise ValueError('Invalid warninglist entry')
            if kind == 'cidr':
                entry = str(ip_network(entry, strict=False))
            elif kind == 'hostname':
                host = entry.lower().lstrip('.').rstrip('.')
                entry = r'(?:^|\.)' + re.escape(host) + '$'
            elif kind == 'string':
                entry = '^' + re.escape(entry) + '$'
            else:
                re.compile(entry)
            normalized.append(entry)
    except (ValueError, re.error) as error:
        abort(400, description=str(error))
    existing = {row.whitelist_artifact for row in whitelist.Whitelist.query.all()}
    added = 0
    for entry in dict.fromkeys(normalized):
        if entry in existing:
            continue
        db.session.add(whitelist.Whitelist(whitelist_artifact=entry,
            notes=json.dumps({'source': 'MISP warninglists', 'name': data.get('name'), 'version': data.get('version')}),
            created_by_user_id=current_user.id, modified_by_user_id=current_user.id))
        added += 1
    db.session.commit()
    from app import cache
    cache.clear()
    return jsonify(added=added, source=data.get('name'), version=data.get('version'))
