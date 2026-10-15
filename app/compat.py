"""Small replacements for removed Python standard-library APIs."""


def strtobool(value):
    if isinstance(value, (bool, int)):
        return bool(value)
    normalized = str(value).lower()
    if normalized in {"y", "yes", "t", "true", "on", "1"}:
        return True
    if normalized in {"n", "no", "f", "false", "off", "0"}:
        return False
    raise ValueError(f"Invalid boolean value: {value!r}")
