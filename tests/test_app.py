"""Functional tests for the REST API (Step 3)."""
import pytest

from app import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True, "LLM_BACKEND": "mock"})
    return app.test_client()


def test_health_check(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"status": "healthy"}


def test_successful_chat(client):
    r = client.post("/api/chat", json={"message": "How can I manage my monthly budget?"})
    assert r.status_code == 200
    assert r.get_json()["response"] == "You can start by tracking your income and expenses."


@pytest.mark.parametrize("msg", ["", "   ", "\n\t"])
def test_empty_message_rejected(client, msg):
    r = client.post("/api/chat", json={"message": msg})
    assert r.status_code == 400
    assert r.get_json() == {"error": "message_empty"}


def test_missing_message_rejected(client):
    r = client.post("/api/chat", json={"text": "hi"})
    assert r.status_code == 400
    assert r.get_json() == {"error": "message_required"}


def test_invalid_json_handled(client):
    r = client.post("/api/chat", data='{"message": "hi"', content_type="application/json")
    assert r.status_code == 400
    assert r.get_json() == {"error": "invalid_json"}
    assert b"Traceback" not in r.data


def test_wrong_content_type_rejected(client):
    r = client.post("/api/chat", data="message=hi", content_type="application/x-www-form-urlencoded")
    assert r.status_code == 415


def test_too_long_message_rejected(client):
    r = client.post("/api/chat", json={"message": "a" * 1001})
    assert r.status_code == 413
    assert r.get_json() == {"error": "message_too_long"}


def test_max_length_message_accepted(client):
    assert client.post("/api/chat", json={"message": "a" * 1000}).status_code == 200


def test_oversized_body_rejected(client):
    r = client.post("/api/chat", data='{"message": "' + "a" * 20000 + '"}', content_type="application/json")
    assert r.status_code == 413
    assert b"Traceback" not in r.data


@pytest.mark.parametrize("value", [123, 1.5, True, None, ["hi"], {"text": "hi"}])
def test_unexpected_type_rejected(client, value):
    r = client.post("/api/chat", json={"message": value})
    assert r.status_code == 400
    assert r.get_json() == {"error": "message_must_be_string"}


@pytest.mark.parametrize("body", ['["message"]', '"hi"', "42", "null"])
def test_non_object_json_rejected(client, body):
    r = client.post("/api/chat", data=body, content_type="application/json")
    assert r.status_code == 400
    assert r.get_json() == {"error": "invalid_json"}


def test_unknown_route_returns_json_404(client):
    r = client.get("/admin")
    assert r.status_code == 404
    assert r.get_json() == {"error": "not_found"}


def test_wrong_method_returns_json_405(client):
    r = client.get("/api/chat")
    assert r.status_code == 405
    assert "Werkzeug" not in r.get_data(as_text=True)


def test_security_headers_present(client):
    h = client.get("/health").headers
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in h["Content-Security-Policy"]
    assert h["Cache-Control"] == "no-store"


def test_message_not_logged(client, caplog):
    secret = "my card is 4111111111111111"
    with caplog.at_level("INFO"):
        client.post("/api/chat", json={"message": secret})
    assert secret not in caplog.text
    assert "4111111111111111" not in caplog.text
