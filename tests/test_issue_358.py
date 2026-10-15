import sys
import pytest
from werkzeug.exceptions import PreconditionFailed
from app import db
from app.models.cfg_states import Cfg_states
from app.models.cfg_settings import Cfg_settings
from app.dynamic_whitelist import validate_dynamic_whitelist


def test_dynamic_release_check_obeys_per_indicator_codes_and_fails_closed(
    client, tmp_path
):
    script = tmp_path / "check.py"
    script.write_text(
        'import json,sys\nprint(json.dumps([int(ip.endswith(".2")) for ip in json.loads(sys.argv[1])]))\n'
    )
    db.session.execute(
        Cfg_states.__table__.insert().values(state="Released", is_release_state=1)
    )
    setting = Cfg_settings(
        key="WHITELIST_SCRIPT_IP_TEST", value=f"{sys.executable} {script}"
    )
    db.session.add(setting)
    db.session.commit()
    validate_dynamic_whitelist(["192.0.2.1"], "IP", "Released")
    with pytest.raises(PreconditionFailed):
        validate_dynamic_whitelist(["192.0.2.1", "192.0.2.2"], "IP", "Released")
    script.write_text('print("invalid result")')
    with pytest.raises(PreconditionFailed):
        validate_dynamic_whitelist(["192.0.2.1"], "IP", "Released")
