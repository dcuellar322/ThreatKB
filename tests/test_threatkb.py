from app.compat import strtobool
import pytest


def test_startup_and_public_routes(client):
    for path in ("/ThreatKB/version", "/ThreatKB/documentation"):
        assert client.get(path).status_code == 200


def test_login_and_protected_route(authenticated):
    response = authenticated.get("/ThreatKB/users/me")
    assert response.status_code == 200
    assert response.json["email"] == "analyst@example.test"


def test_boolean_compatibility():
    assert strtobool("true") is True
    assert strtobool(False) is False
    assert strtobool(1) is True
    with pytest.raises(ValueError):
        strtobool("maybe")
