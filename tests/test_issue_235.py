def test_invalid_and_unknown_login_are_401(client, caplog):
    for email in ("unknown@example.test", "analyst@example.test"):
        response = client.post(
            "/ThreatKB/login",
            json={"email": email, "password": "private-invalid-password"},
        )
        assert response.status_code == 401
        assert response.json["user"] is None
    assert "private-invalid-password" not in caplog.text
    assert client.post("/ThreatKB/login", json={}).status_code == 400


def test_anonymous_exception_does_not_break_error_handler(client):
    response = client.get("/ThreatKB/exception")
    assert response.status_code == 500
    assert response.json == {"error": "An internal error occurred."}
