from app import app, db, bcrypt, admin_only, auto
from app.models.users import KBUser
from app.models import yara_rule, c2dns, c2ip, tasks, users
from flask import request, jsonify, session, json, abort, send_file, Response
from flask.ext.login import current_user, login_required
import flask_login
import tempfile
import uuid


@app.route('/ThreatKB/login', methods=['POST'])
@auto.doc()
def login():
    """Log a user into ThreatKB.
    Return: user dictionary"""
    app.logger.info("login called with payload: '%s'" % request.data)
    json_data = request.json
    user = KBUser.query.filter_by(email=json_data.get('email', None), active=True).first()
    app.logger.info("user is '%s'" % user)
    if user and bcrypt.check_password_hash(user.password, json_data['password']):
        session['logged_in'] = True
        s = True
        flask_login.login_user(user)
        is_admin = user.admin
    else:
        s = False
        is_admin = False
    return jsonify({'result': s, 'a': is_admin, 'user': user.to_dict()})


@app.route('/ThreatKB/logout')
@auto.doc()
@login_required
def logout():
    """Log a user out of ThreatKB.
    Return: result dictionary"""
    session.pop('logged_in', None)
    flask_login.logout_user()
    return jsonify({'result': 'success'})


@app.route('/ThreatKB/users', methods=['GET'])
@auto.doc()
@login_required
def get_all_users():
    """Return all users.
    Optional Arguments: include_inactive
    Return: list of user dictionaries"""
    include_inactive = request.args.get("include_inactive", False)

    if not include_inactive:
        users = KBUser.query.filter(KBUser.active > 0).order_by(KBUser.email).all()
    else:
        users = KBUser.query.order_by(KBUser.email).all()

    users = [user.to_dict() for user in users]
    users.append({"email": "Clear Owner"})
    return Response(json.dumps(users), mimetype='application/json')


@app.route('/ThreatKB/users/<int:user_id>', methods=['GET'])
@auto.doc()
@login_required
@admin_only()
def get_user_by_id(user_id):
    """Return the user associated with the given user id.
    Return: user dictionary"""
    user = KBUser.query.get(user_id)
    if not user:
        abort(404)
    return jsonify(user.to_dict())


@app.route('/ThreatKB/users/me', methods=['GET'])
@auto.doc()
@login_required
def get_user_me():
    """Return the user associated with the given user id.
    Return: user dictionary"""
    user = KBUser.query.get(current_user.id)
    if not user:
        abort(404)
    return jsonify(user.to_dict())


@app.route('/ThreatKB/users/me/picture', methods=['GET'])
@auto.doc()
@login_required
def get_user_me_picture():
    """Return the user associated with the given user id.
    Return: user dictionary"""
    return get_user_picture_by_id(current_user.id)


@app.route('/ThreatKB/users/me/picture', methods=['POST'])
@auto.doc()
@login_required
def update_user_me_picture():
    """Return the user associated with the given user id.
    Return: user dictionary"""
    if 'file' not in request.files:
        return jsonify(fileStatus=False)

    f = request.files['file']

    if f.filename == '':
        return jsonify(fileStatus=False)

    picture = f.stream.read()
    current_user.picture = picture
    db.session.add(current_user)
    db.session.commit()
    # db.engine.execute("UPDATE kb_users SET picture=:picture WHERE kb_users.id=:id", {"picture": picture, "id": current_user.id})

    return get_user_picture_by_id(current_user.id)


@app.route('/ThreatKB/users/me/password', methods=['PUT'])
@auto.doc()
@login_required
def update_my_password():
    """Update the user's password associated with the given user_id
    From Data: email (str), admin (bool), password (str), active (bool)
    Return: user dictionary"""

    old_password = request.json.get("old_password", None)
    new_password1 = request.json.get("new_password1", None)
    new_password2 = request.json.get("new_password2", None)

    if not old_password or not new_password1 or not new_password2:
        abort(404)

    if not bcrypt.check_password_hash(current_user.password, old_password):
        abort(401)

    if not new_password1 == new_password2:
        abort(400, description="New passwords not identical.")

    current_user.password = bcrypt.generate_password_hash(new_password1)
    db.session.add(current_user)
    db.session.commit()

    return jsonify(current_user.to_dict()), 200


@app.route('/ThreatKB/users/<int:user_id>/picture', methods=['GET'])
@auto.doc()
@login_required
def get_user_picture_by_id(user_id):
    """Return the user's picture as a binary image.
    Return: user image"""
    user = KBUser.query.get(user_id)
    if not user:
        abort(404)

    temp_file = "%s/%s" % (tempfile.gettempdir(), str(uuid.uuid4()).replace("-", ""))
    content = user.picture if user.picture else '\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\xc8\x00\x00\x00\xc8\x08\x02\x00\x00\x00":9\xc9\x00\x00\x10\x1bIDATx\xda\xed\x9dYW\x1bI\x96\x80\xef\x8dL)\xb5\xefBb5`\x8c\x01\x1b/\xe5\xb2\xdd\xaes\xbaj\xba\xcf\xbc\xce\xd3\xfc\xa9\xfe\x0b\xfd\x07\xe6\x8f\xcc\x99\xa9qW\xb9(\xdb\x80\xc1\xc66f\x95\x10\x08\x90\xd0\x9e\x99w\x1e\xd2vW\xbb\xc0[\x91\xe4\x8dT|\xcf,7#\xbe\x88\xb8\xb1e\xe2\xdf\xfe\xfe_\xa0P\x9c7\xc2\xeb\x00\x14\xfeD\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\xf7:\x009 \x02\x00\x02\x00\x00D\xf4:\x1a\x19Pb\x9d\t\x11\x11\x81\xa6\x89\x80\xaek\x9ap\x84""\xcb\xb2{\xa6iY6\xa2\xb2\xecL\x94X\x1fb\x13\t!\xc2F0\x93J\xe43\xa9t2\x1e\x8fF"\xe1\x90\xaek\x00`\x9aV\xb3\xd5\xae7\x9a\x87\xc7\xf5J\xf5\xa8zTku\xba\xb6m\x0be\xd8\xbf\xa2\xc4z\x0b\x11\x01\x80\x11\x0c\x0ed\xd3\xe3#\xc5\xe1b>\x19\x8f\x05\x83\x01\r\x91~\xf7\xc3\x08`\x11u\xbb\xbd\xe3\xfa\xc9v\xa9\xb2\xbeU\xda\xab\x1ev:]P#\xe5;\x94Xo\x95\x8a\x84CcC\x85\xab\x93c\xc5|6d\x04\x01\x80\x80\x80\xc0&:\xe5W\x00\x10\xc00\x02\x05#S\xc8e\xe6\xaeL\x94*\x07\xab\xaf77\xb6K\xcdV\x1b\x94^J,"2\x82\xc1\x89\xd1\xe2\xf5\xe9\xcb\x85\\Z\xd7uz\xa7\xdag\xfc2\x10\x10\x00\x18Fp|dp\xa4\x98/\xef\x1f.>\x7f\xf9z\xb3\xd4\xe9v\xfb\xdc\xad\xfe\x15\x8b\x88\x84\x10\xc3\xc5\xfc\xed\xb9\xe9\xd1\xa1\x81\x80\xae\x93\x93\xae\x7f\xdd\xdf\x02\xd04m\xb8\x98\x1f\xc8\xa57w\xf6\x16\x96\x9f\xef\x94\xf7m\xdb\xee[\xbd\xfaT,"\x8aE\xc37f\xa6\xe6\xa6\xc6\xa3\x910|\xb5R\xbf\xfb\xb3\x01M\x9b\x1c\x1b*\xe4\xd2\xcbk\xebOV\xd6N\x1a\xad\xfet\xab\xef\xc4"\x00\x81828p\xf7\xc6\xecp1/\x10\xcfE\xa9\xdf\xfe} \x8aF\xc2w\xe6g\x8a\xf9\xecOO\x9em\x97*6Q\xbf\xc9\xd5_b\x11Q0\xa0\xcf]\x99\xf8\xe6\xfa\xd5x4\xf2\xf5c\xdfg\xfc#\x04\x18\x1d\x1cH\'b\x8f\x16W\x97_\xbc\xee\xf6\xcc\xbe\xea\xba\xfaH,"\x8aE"wo\xce\xceN]r2\xaa\x8b\xf8\x8f\xd1\xc8ww\xe6\xd3\xc9\xc4O\x8f\x97O\x9a}4,\xf6\x8bXD\x94M%\xbf\xfbv~|d\x10?\x7f\xdew\x1e\xffW\xd7\xb4\xf9\xab\x93\xf1h\xf8\x7f~~zpt\xdc\'n\xf5\x85XDP\xccg\xbf\xbfwsp waJ}\xc0\xc4\xe8P(d\xfc\xf7?\x1e\xef\xee\x1d\xf4\x83Z\xfe?\xdd@\x04#\x83\xf9\xbf~w\xc7C\xab\x00\x80\x88\x06\xf3\xd9\xbf>\xb83:8\xe0]\x14\x17\x87\xcf\xc5"\x80K\xc3\x85\xbf<\xf8&\x9fIyh\xd5\xdb`\x88r\x99\xe4\xbf=\xb8=64\xe0{\xb5\xfc,\x16\x01\x8c\r\x0e\xfcp\xffv&\x99\xf0\xdc\xaa\xb7!\x11e\x92\x89\x1f\xee\xdf\x1e-\xe6\xbd\x8e\xc5]|+\x16\x11\r\x0ed\xbf\xbfw+\x9d\x8c3\xb1\xea}`\x99T\xe2\x87\xfb\xb7\x8b\x03YV\x81\x9d/\xfe\x14\x8b\x88r\x99\xd4\xf7wof\xd3I\x86\x95GD\xd9t\xf2\xfb\xbb7s\x0c\x06h\x97\xf0\xa1XD\x94\x88E\xff|\xf7f1\xcf\xb7K \xa2b>\xfb\xe7\xbb7\x13\xb1(\xdb \xff\x08~\x13\x8b\x08BF\xf0O\xb7\xaf\x8d\x0e\x0e0\xaf0"\x1a\x1d\x1c\xf8\xd3\xedk!#\xc8;\xd2\xaf\xc1obi\x9a\xb85wezb\xcc\xeb@>\x97\xe9\x89\xb1[\xd7\xa65\xcdo\x15\xe1\xb7\xe7\xb9ri\xe4\xe6\xec\x15M\x93f\tR\xd3\xf0\xe6\xcc\xd4\x95\xf1\x11\xaf\x039g\xfc#\x16\x11\x15\xb2\xe9{\xb7f\xe5\x1aY\x9c\xb1\xfb\xde\xcd\xb9B.\xc3|\xec\xfe"|"\x16\x11E\xc2\xa1{\xb7\xe6\xd2l\x96\xac\xbe(\xf8t2~\xff\xe6l$\x1c\x92.\xf8\xb3\xf0\x89XB\x88\xf9\xab\x97\xc7\x86\x8b\x92V\x0c\x11\x8d\x0e\x17o\\\xbd\xac\t\xbf\xd4\x88\xd7\x01\x9c\x03D46T\xb81#w\xadhB\xcc\xcf\\\x1e\x1d*H\xda6>@\xe2\x9app\xce<};?#\xfb8\xe2\x8c\xe6\xdf\xce\xcf\xc4\xa2\x11\xa9\x1f\xc4Az\xb1\x84\x10\xf3W\'\x07\x0b^\x9e\\8/\x88h\xb0\x90\x9b\xbf:)d\xeez\x1d\xe4~\x00"\x1a\x1c\xc8\xcdMM\xf8\xe6"\xb2@\x9c\x9b\x9a\xf0\xf6\x84\xcf\xf9<\x88\xd7\x01\xfc!\x8c`\xe0\xd6\xecT,\x1a\x96\xbd\x1a\xde\xe3\\\x1f\xba5;e\x04\x03^\xc7\xf2\x87\x90X,"\x9a\x1c\x1b\xbe$\xedL\xf0#\xcfui\xb8896,\xf5s\xc9*\x16\x11\xc5\xa3\x91\x1b3\x97\x03\x01\x1f\x9e\xae\x0e\x04\xf4\x1b3\x97\xe32g\xf1\xb2\x8a\x85\x88\xd3\x93\xa3\x03\xd9\xb4\xbcE\xff\x11\x88h \x9b\x9e\x9e\x1c\x95\xf7\xe6\x85\x94b\x11Q*\x11\x9b\xbd<\xee\x83\xd9\xd3Y\x08!f/\x8f\xa7\x121I[\x8e\x94\x15\x83\x88W\'\xc72)\xf9vo>\x1f\xe7\xa0\xe9\xd5\xc91I;-\xf9\xc4r\xba\xab\xe9\tYK\xfc\xf3A\xc4\xe9\x89\xb1t\x82\xd7\xd1\xea\xcfD>\xb1\x10\xf1\xca\xc4\xa8\xbcc\xc4\xe7\xe34\xa1\xa9\t)3-\xc9\xc4"\xa2D<:=.eY\x7f\x05\x888=>\x92\x8c\xcbw|Y2\xb1\x00`bd\x90\xdb\xc5\x1b\xf7pN\xd4L\x8c\x0cy\x1d\xc8\x17#\x93XD\x10\t\x87\xae\x8c\x8f\xfax2\xf8{\x84\x10S\xe3#\x91pH\xae\xa6$W\r\xd1H1\x9f\xcf\xfa\xf6\xca\xd4\xe9\xcfL\x94\xcf\xa6F\x8a\xf9w/\x9a\x97\x03\x99\xc4\xd2u\xfd\xf2\xa5\x91\x80\xee\xc3\xa5\xf6\x8f\x13\xd0\xf5\xa9\xf1\x11\xb9\xf6\x18\xa4\x11\x8b\x88\xb2\xa9\xc4P!\xe7u \xde<\xfdP!\x97Mq\xbc|{\x16\xd2\x88\x85\x88\xe3#\x83Q\xc9O\xf3}\x1dD\x10\t\x85\xc6G\x8a\x12\xcd\x85\xe5\x10\x8b\x08\xc2!C\xae\x92=_\x10\xf1\xd2\xf0`$d\xc8\xd2\xac\xe4\x10\x0b\x80\x8a\xb9\x8c\xbf\xf7p>\xf1\xfcD\x99T\xbc\x90\xcb\xc8\x92\xc2\xcb!\x96\x10bt\xa8\x10\x0c\xc8}\xf6\xed\x0f\x12\x0c\x04F\x87\x0b\xb2,\xb5H\x10\xa5s\xcb`\xd8\xef/\x94\xfa\x1c\x86\x0byY\xee\x8c\xc8 \x16@>\x93\x92q[\xe3\x9c\xcb\x81(\x19\x8f\xe63))JA\x02\xb1\x04\xe2P!\xd7\xe7\xe3\xa0C0\x10\x18.\xe4\xa5\xb89\xc2],\x02\x08\x19\xc1\xa1\x81\xfe\\\xbe:\x85\xc1BV\x8a\x97Sp\x17\x0b\x88\xd2\xc9D:\x19\x07\xfeey\x01\x10\xa5\x13\xf1t2\xc1\x7fn\xc8^,\x80b.\x1d2\x82\xdc\x0b\xf2Bp\xfa\xefb.\xedu \x9f\x86\xbbX\xba\xae\x0f\xe42Rd\x15\x17\x83@,\xe42\xfc7LY\x8bEDa#(\xcb<\xe8b \x80\\&\x152\x82\xcc\xe7\xc8\xac\xc5\x02\x80t2\xde\x9f\xfb\x83gAD\xd1p(\x9d\x8c{\x1d\xc8\'\xe0.V.\x9d\x0cJ~\xd9\xfc\xdc\t\x06\x03\xd9t\x92ySc-\x96\xa6i\x99tR%X\x1f \x103\xa9\x84\xce\xfb}\xb8|\x83#\x82`@\xcf$\x13\xcc\x9b\xe6\xc5C\x00\xd9T"\x18\x08pN\x10\xf8\x8a\x05@\x91p(\x1e\x8bx\x1d\x06G\xe2\xb1h$\x1c\xe2\xbc\x9a\xc5Y,H%b\xc1\xc0E|\nU.\x9c\x0f\x10\xa7\x121\xaf\x03\xf9\x18|\xc5"\x82d<\xc6\x7f\xc1\xc6\x13\x02\xba\x9e\x8c\xc78\xb78\xbebi\x9aH\xc4\xa2B\xa8\xcc\xfd\x14\x84\xc0d<\xca\xf9{\x16|#\xd3u-\x11\x8brn\x94\x1eB\x04\x89hT\xd75\xaf\x039\x13\xa6b\x11Q@\xd3\xe2\xd1\xb0\xd7\x81\xf0%\x16\r\x074\x8dm\x02\xcaT,\x000\x8c`8dx\x1d\x05_B!\xc30\x82^Gq&|\xc5\x8a\x86C\x9a\xa6\xa9\xd32\xa7C\xa4kZ4\xcc\xb7Gg*\x16\x01D\xc2!]\x13J\xabS!\x00]\x13\x91\xb0\xc1\xb6|\x98\x8a\x05\x04!\xc3\x10\x1a\xdf\xe4\xd4s4M\x0b\x87\x0c\xb6K\xa4\\\xc5B\x08\x87\x82\x9a\xda%<\x1b!0d\x04\x81k\t1\x15K\x13"d\x18lK\x8d\t!\xc3`\xfb]*\xaea9\xcd\x91k?\xcf\x02\x82\x90\x11d\xbb\x80\xccU,\x14\x01]W^}\x04\x02\x08\xe8\xba@\xae5\xe8u\x00\xa7@\x00B\xa0\\\xaf\x83\xf2\x84@@\x17\x02y6?\x8eb\x01\x01"\xaa\xed\xe7O\x12\xd4uD\xe4\x990\xb0\x14\x0bH\x08\x11`\xbc\x11\xc6\x04]\xd7\x84\x10<Oe\xf1\x14\x0b\x10@\x96\xd7\xaax\x88\xd0\xb8\xa6\xeel\xc5\x02Du\xd4\xfd\x93\x08D\xe0ZJL\xc5B\x00\xb6\x13i>\x08\xc6/8\xe4*\x96@\xc6\x85\xc6\x05DD\xae\xcd\x8f\xa9X,\xf3Q\x8e \xd7\xdd\t\xa6b\x11\x91\xad\x0e\xcc|\n\x02\xb0m\xdb\xeb(N\x87\xabX\x00d+\xb1>\x81m\xf3-#\xaeb\x11\x99\\\xdb"\x1fL\xcbVG\x93\xbf\x08\xb4m\xbb\xd7\xeby\x1d\x06wz\xbd\x9em\xdb\xc02\xcd\xe2(\x16"\xd86u{\xa6\xd7\x81p\xa7\xdb3m\x9bx\xce\x9e9\x8a\x05\x006\xd9\xddn\x8fe\x89q\x01\x01\xba\xdd\x9eML\x13\x06\xa6bY\x96\xddjwX\xf6\xf1l@h\xb5;\x96\xa5\xc4\xfa\x12l\xdbn\xb6;j5\xeb\xe3\xb4\xda\x1d\xb5\xdc\xf0e\x10A\xb3\xd5\xb6\xb8\x96\x1a\x07,\xcbn\xb4\xda\\\'\x85\\\xc5B\x84z\xa3i\x9a\x96\xd7\x81\xf0\xc54\xadz\xa3\xc93s\x07\xb6b\x01@\xbd\xd1\xecY\x96\xda1<\x15D4-\xab\xdehz\x1d\xc8\x99\xf0\x15\xab\xd5\xee\xb4\xdam\xaf\xa3\xe0K\xb3\xddi\xb5;^Gq&L\xc5B\xc4n\xafwx\\W\xfd\xd5\xa9 \xc0\xe1q\xad\xdb\xeb\xb1\xed\xd1\x99\x8a\x05\x00\xbd\x9eyx\\\xe7\x9a\x9bz\x0c\x01\x1c\x1e\xd7{\x8c\xd7\x90\xf9\x8aE\x00\xd5\xa3\x9a\xca\xdfO\xc54\xad\xeaQ\x8ds\xab\xe3+\x16\x02\xec\x1f\x1e\xb7;\x1d\xb6\xbd\xbdW b\xbb\xd3\xdd?<\xe6\\.|\xc5\x02\xc4F\xb3uX;\xf1:\x0e\x8e\x1c\xd6\xea\x8df\x8b\xed\x81w\xe0,\x16\x02t\xba\xbd\xf2~\xd5\xeb@8\xb2\xb7\x7f\xd8\xe1\xbd\x97\xcaW,\x00\xb0\x89v\xf7\x0e\xd4\xf9\x99\x0f\xe8\xf5z\xbb\x95}\xb6\'\xb1\x1cX\x8b\x85\x00\x95\xeaa\xad\xd1Ti\xd6{\x10\xb1\xdehU\x0e\x8e\xbc\x0e\xe4\x13\xf0\x16\x0b\xb1\xd9\xea\xec\x96\x0f\xbc\x0e\x84\x17;{\xfb\x8dV\x9bycc-\x16\x00\x98\x96\xb5\xb1[\xee\x99|\x17l.\x98\x9ein\xec\x94M\x8b\xfb*\x0cw\xb1\x10\xa0\xb4wp\\;a\xde@/\xa84\x10\x8fk\'\xa5\xbd\x03\xfee\xc1^,\xc4F\xab\xbd\xbe]R\xafO\x06\x00 Z\xdf.\xf1\x1f\x07\x81\xbfX\x00`\xdb\xf6\xfa\xe6N\xab\xd3e_\x98\xee\x82\x08\xadNw}s\x87\xed\xe1\xbe\xdf"\x81X\x88X\xa9\x1eo\x97+<\xaf\xa3\\dIl\x97+\x95\xea1\xff\xee\n\xa4\x10\x0b\x00\xba\xbd\xde\x8b\xd7[}\x9e\xc2\xf7z\xe6\x8b\xd7\x9b]IV\xf5\xe4\x10\x0b\x107w\xcb\xe5JU\x8a\xc6\xeaN\x01`y\xbf\xba\xb9\xbb\xc7y\x1b\xe7\xb7\xc8!\x16\x02\xb4\xda\x9d\xe5\xb5u\xb3_;-\xd34\x97_\xae\xb7\xda\x1d9\xb4\x92E,\x00\x00\xc4\xf5\xad\xd2n_vZ\x88\xb8[\xa9\xaeo\x95d\xe9\xae@"\xb1\x10\xa0\xd5n/\xae\xbe\x92%\xc98G\xba\xbd\xde\xe2\xf3W\xadV[\x1a\xad$\x12\x0b\x00\x10q}{wc\xbb\xdcW\x9d\x16"nl\x97\xd7\xb7v\xe5zj\x99\xc4\x02\x80n\xb7\xf7xe\xad\xd1l\xc9U\xca_\r"6Z\xad\xc7+k\xdd\xaed\xfd\xb4db!\xe2Ny\x7fym\xbdO^\xcbf\x13-\xbfX\xdf-\xefK\xd7\x90$\x13\x0b\x00l\xdb^\\}U\xae\x1cHW\xd6_\n"\x96+\x07\x8b\xab\xafd\xbc\x11.\x9fX\x88X;i\xfc\xf4d\xa5\xd9\xf6\xf3qxDl\xb5;??Y\xa9\x9d4d|L\xf9\xc4\x02\'\x9f\xdd)-\xae\xbe\x94b\xd7\xec\xeb\xb0m\xfb\xe9\xea\xcb7;%\x19\xad\x02I\xc5\x02\x00\xcb\xb2\x1f?[{-\xdb\\\xe93A\xc4\xd7[\xbb\x8f\x9f\xad\xb1}K\xd1\'\x91U,Dl\xb6\xda\x0f\x17\x96*\xd5#\x9f\xb9\x85\x88\xfb\xd5\xa3\x87\x0bKM\x19\x8e\xc7\x9c\x85\xacb\xc1\xdbS\x0fG?.,\x9e\xf8h\xf5\x01\x11O\x9a\xad\x1f\x17\x16eo0\x12\x8b\x05\xce\x92\xe9V\xe9\xe1\xafK\xedNW\xe2J\xf8\xe7\xe3@\xbb\xd3}\xb8\xb0\xf4zK\xd6\xd4\xea=r\x8b\x05\x00@\xf4l\xed\xcd\xcfOV\xba\xf2\xefOw{\xe6\xcfO\x9e={\xb9\xee\x83\xe3\xb2\xf2\x8b\x05`\xdb\xf6\x93\x95\xb5\x85\xc5\xe7\xfc\xaf\x18|\x04\xd3\xb2\x16\x16\x9f?Yy\xc9\xf8\xab\x00_\x80\x1f\xc4\x02\x00\xd3\xb2\x1e-\xad>z\xbaj\x9a\x96tc\x08"\x98\xa6\xf5\xe8\xe9\xea\xa3\xa5U\xa9\xdb\xc6o\xf1\xcf\xe7qM\xd3\xfaeq\xd5\xb6\xed;\xf33F0\xc0\xfc\xa2\xf0{\x10\xb1\xd3\xed=z\xba\xf2\xeb\xf2\x0b\xdfX\x05~\x12\x0b\x00L\xcb\xfae\xe9y\xbb\xd3\xb9\x7f\xebZ4\x12\xe6\xef\x96\xb3\xc7\xfcpayym\xddg\x8b\xbd\xbe\x12\x0b\x00l\xdb^z\xb1\xdelu\x1e|s=\x9bNrv\x0b\x11\xab\x87\xb5\xff]x\xfazs\x97s\x9c_\x87\xdf\xc4\x02\x00"z\xb9\xb1]o4\x1f|s}l\xa8 \x84\xe0Vm\x88h\xdb\xf6\x9b\xed\xd2\xff-,\x95\xf7\xfdy&V\xfb\xf7\xff\xf8O\xafc8\x7f\x10\xb1\xd1lm\xed\xee\xd96eR\x89@\x80Q\xfbqv\x97\x1f/\xaf\xfd\xf8\xcb\xd3\xc3Z\xdd\x97V\x81/{,\x07\xe7\n\xf5\xc3\xc7\xcb\xa5\xfd\x83;\xd7g\x8a\xf9\xac\x10\xe8m\xd7\x85\x88\xb6M\xbb{\xfb\x8f\x16W\xdel\x97-_\xbfl\xdc\xb7b\xc1\xbb\x11\xe7\xd5\xc6N\xa5zt\xed\xca\xe4\xdc\xd4x<\x16\x01\x80\x8b\xd7\xcb\x11\xa8~\xd2\\^[_z\xf1\xaa~\xd2D\xf4\xf9G\xaf\xfd,\x96\x03"\xd6O\x9a\xff\xf8u\xf9\xcd\xd6\xee\xf5\xab\x97\'F\x07\xc3!\x03.J/\xc7\x9eV\xbb\xf3zswq\xf5ey\xff\xd0&\xdb\xdfJ9\xf8_,\x00@D\x02\xda\xad\x1cT\x0e\x8fW_eg\xa7\xc6\xc7\x86\n\x91p\x08\xdc\xd4\xcb\xb1\xa7\xd9jo\xec\x94\x9f\xad\xad\xef\xec\x1d\x98\xa6\xe9\xfb\x8e\xea=}!\x96\x03"Z\x96\xb5\xb1S\xde\xd9;\x18\xc8\xa6\xae\x8c\x8f^\x1a.&\xe2Q]\x13D\xe7f\x98c\x8ei\xd9\xb5\xda\xc9\x9b\xed\xd2\xda\xfaf\xf9\xe0\xa8\xaf\x94r\xe8#\xb1\x1c\x1c\xbdv\xca\xfb\xa5J\xf5\xf1\xb3\xb5\x91b~l\xa8P\xc8e\xa2\x91\x90\xaei\x8e\\_*\x99c\x0c\x02\x98\x96\xd5h\xb6\xcb\xfb\xd5\x8d\x9d\xf2V\xa9R;i\xd8\xb6\xddoJ9\xf4\x9dX\x0e\x88HDG\xb5\xfaa\xad\xbe\xfaj#\x1e\x8b\x14\xf3\x99B.\x9b\xcf$\x13\xb1h0\x10\x08\xe8\x1a\n\x04:\xf3\x93\x89\x8eJdS\xcf\xb4\xba\xbd^\xed\xa4Q\xa9\x1e\x97\xf7\x0fJ\x95j\xfd\xa4\xd95M|\xdb{\xf5\x9dR\x0e}*\x96\x83S\xed\xa6eU\x8fj\xd5\xa3\xda\xca\xcb\r#\x18\x88\x84C\xe9D<\x19\x8f\xc5c\x91H\xc8\x08\x19\xc1`0\xa0k\x9a\x10\x02\x00l\xdb6-\xab\xdb\xed\xb5;\xddf\xbbS?i\x1e\xd7O\x0ek\xf5f\xab\xdd\xe9:\x9f\xfe\x06D\x14\xfd\xea\xd3{\xfaZ\xac\xf78\xfd\n\x11\xb5;\xddV\xbb\xb3\x7fx\x0c\x04\x9a@M\xd34M\x08D\x14oU!\x02\xb2m\x9b\xc8\xb2l\xcb\xb2,\x9b\x00\x01\xdf\x8f\x86}\xef\xd3{\x94X\x1f\x82\xef2&\x020-\xcb\xb4,"\x80\x7f\x19\x12\xff\xe9\x8f\x10\xca\xa4\xd3Qb}\x9aw\xa9\xb9\xe2\x0b\xf0\xc9A?\x057\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\x94X\nWPb)\\A\x89\xa5p\x05%\x96\xc2\x15\xfe\x1f\x17\xccx\xa5e\xe9e\xf9\x00\x00\x00\x00IEND\xaeB`\x82'
    with open(temp_file, "wb") as f:
        f.write(content)

    return send_file(temp_file)

@app.route('/ThreatKB/users', methods=['POST'])
@auto.doc()
@login_required
@admin_only()
def create_user():
    """Create a user.
    From Data: email (str), admin (bool), password (str), active (bool)
    Return: user dictionary"""
    user = KBUser(
        email=request.json['email'],
        admin=request.json['admin'],
        password=bcrypt.generate_password_hash(request.json['password']),
        active=request.json['active']
    )

    db.session.add(user)
    db.session.commit()

    return jsonify(user.to_dict()), 201


@app.route('/ThreatKB/users/<int:user_id>', methods=['PUT'])
@auto.doc()
@login_required
def update_user(user_id):
    """Update the user associated with the given user_id
    From Data: email (str), admin (bool), password (str), active (bool)
    Return: user dictionary"""
    user = KBUser.query.get(user_id)
    if not user:
        abort(404)

    if not current_user.admin and not user.id == current_user.id:
        return abort(403)

    user = KBUser(
        email=request.json['email'],
        password=bcrypt.generate_password_hash(request.json['password'])
        if 'password' in request.json else user.password,
        admin=request.json['admin'],
        active=request.json['active'],
        first_name=request.json.get('first_name', ""),
        last_name=request.json.get('last_name', ""),
        id=user.id
    )

    if not user.active:
        yara_rule.Yara_rule.query.filter(yara_rule.Yara_rule.owner_user_id == user_id).update(dict(owner_user_id=None))
        c2dns.C2dns.query.filter(c2dns.C2dns.owner_user_id == user_id).update(dict(owner_user_id=None))
        c2ip.C2ip.query.filter(c2ip.C2ip.owner_user_id == user_id).update(dict(owner_user_id=None))

    db.session.merge(user)
    db.session.commit()
    user = KBUser.query.get(user_id)

    return jsonify(user.to_dict()), 200


@app.route('/ThreatKB/status')
@auto.doc()
def status():
    """Get the login status of the current user session.
    Return: status dictionary"""
    app.logger.debug("status current_user is '%s'" % (str(current_user)))
    if session.get('logged_in'):
        if session['logged_in']:
            return jsonify({'status': True, 'a': current_user.admin, 'user': current_user.to_dict()})
    else:
        return jsonify({'status': False, 'a': False, 'user': None})


@app.route('/ThreatKB/users/ownership', methods=['GET'])
@auto.doc()
@login_required
def get_users_ownership():
    """Return all user ownership information.
    Optional Arguments: include_inactive
    Return: dictionary of user ownership assignments"""
    include_inactive = request.args.get("include_inactive", False)
    include_artifacts = request.args.get("include_artifacts", False)

    ownership_data = {"!Unassigned": {"task": [], "ip": [], "dns": [], "signatures": []}}
    u = {user.id: user for user in users.KBUser.query.all()}
    for user_id, user in u.iteritems():
        ownership_data[user.email] = {"task": [], "ip": [], "dns": [], "signatures": []}

    t = tasks.Tasks.query.all() if not include_inactive else tasks.Tasks.query.filter(tasks.Tasks.active > 0).all()
    for task in t:
        if task.owner_user_id:
            ownership_data[u[task.owner_user_id].email]["task"].append(task.to_dict() if include_artifacts else task.id)
        else:
            ownership_data["!Unassigned"]["task"].append(task.to_dict() if include_artifacts else task.id)

    ips = c2ip.C2ip.query.all()
    for ip in ips:
        if ip.owner_user_id:
            ownership_data[u[ip.owner_user_id].email]["ip"].append(ip.to_dict() if include_artifacts else ip.id)
        else:
            ownership_data["!Unassigned"]["ip"].append(ip.to_dict() if include_artifacts else ip.id)

    dnss = c2dns.C2dns.query.all()
    for dns in dnss:
        if dns.owner_user_id:
            ownership_data[u[dns.owner_user_id].email]["dns"].append(dns.to_dict() if include_artifacts else dns.id)
        else:
            ownership_data["!Unassigned"]["dns"].append(dns.to_dict() if include_artifacts else dns.id)

    signatures = yara_rule.Yara_rule.query.all() if not include_inactive else yara_rule.Yara_rule.query.filter_by(
        yara_rule.Yara_rule.active > 0).all()
    for signature in signatures:
        if signature.owner_user_id:
            ownership_data[u[signature.owner_user_id].email]["signatures"].append(
                signature.to_dict() if include_artifacts else signature.id)
        else:
            ownership_data["!Unassigned"]["signatures"].append(
                signature.to_dict() if include_artifacts else signature.id)

    return Response(json.dumps(
        [{"email": email, "ownership_data": ownership_data} for email, ownership_data in ownership_data.iteritems()]),
                    mimetype="application/json")
