import yara
from flask import request, jsonify, abort
from flask_login import login_required
from app import app
from app.detection import compile_active_rules


@app.post("/ThreatKB/scan")
@login_required
def scan_upload():
    """Scan an upload in memory using all active signatures; discard it afterward."""
    upload = request.files.get("file")
    if not upload or not upload.filename:
        abort(400, description="Choose a file to scan.")
    data = upload.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        abort(413, description="Scanner uploads are limited to 16 MiB.")
    try:
        matches = compile_active_rules().match(data=data, timeout=15)
    except yara.SyntaxError as error:
        abort(422, description=f"Active rules do not compile: {error}")
    except yara.TimeoutError:
        abort(408, description="Scan exceeded its time limit.")
    return jsonify(matches=[{
        "rule": match.rule,
        "strings": [{"identifier": string.identifier,
                     "instances": [{"offset": instance.offset,
                                    "data_hex": instance.matched_data.hex()}
                                   for instance in string.instances]}
                    for string in match.strings],
    } for match in matches], bytes_scanned=len(data))
