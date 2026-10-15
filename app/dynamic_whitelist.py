"""Bounded, shell-free dynamic indicator release checks."""
import json
import shlex
import subprocess
from flask import abort
from app.models.cfg_settings import Cfg_settings
from app.models.cfg_states import Cfg_states


def validate_dynamic_whitelist(indicators, kind, state):
    release = Cfg_states.query.filter_by(is_release_state=1).first()
    if not release or release.state != state:
        return
    scripts = Cfg_settings.query.filter(Cfg_settings.key.like(f'WHITELIST_SCRIPT_{kind}_%')).all()
    timeout = float(Cfg_settings.get_setting('WHITELIST_SCRIPT_TIMEOUT') or 10)
    timeout = min(60, max(0.1, timeout))
    for script in scripts:
        if not script.value:
            continue
        try:
            result = subprocess.run([*shlex.split(script.value), json.dumps(indicators)],
                                    capture_output=True, text=True, timeout=timeout, check=True)
            codes = json.loads(result.stdout)
            if not isinstance(codes, list) or len(codes) != len(indicators) or any(type(code) is not int for code in codes):
                raise ValueError('Expected one integer result per indicator')
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            abort(412, description=f'Dynamic release check {script.key} failed: {error}')
        blocked = [indicator for indicator, code in zip(indicators, codes) if code != 0]
        if blocked:
            abort(412, description=f'Dynamic release check {script.key} blocked: {", ".join(blocked)}')
