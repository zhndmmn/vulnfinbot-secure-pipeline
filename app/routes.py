"""HTTP endpoints: GET /health and POST /api/chat."""
from flask import Blueprint, current_app, g, jsonify, request

from .assistant import answer

bp = Blueprint("api", __name__)


def _bad_request(code: str, status: int = 400):
    return jsonify({"error": code}), status


@bp.get("/")
def index():
    return jsonify({"service": "mini-vulnfinbot", "endpoints": ["/health", "/api/chat"]})


@bp.get("/health")
def health():
    return jsonify({"status": "healthy"})


@bp.post("/api/chat")
def chat():
    if not request.is_json:
        return _bad_request("content_type_must_be_application_json", 415)

    data = request.get_json(silent=True)          # invalid JSON -> None, never a traceback
    if not isinstance(data, dict):
        return _bad_request("invalid_json")

    if "message" not in data:
        return _bad_request("message_required")

    message = data["message"]
    if not isinstance(message, str):
        return _bad_request("message_must_be_string")

    message = message.strip()
    if not message:
        return _bad_request("message_empty")

    if len(message) > current_app.config["MAX_MESSAGE_LENGTH"]:
        return _bad_request("message_too_long", 413)

    # Log metadata only — never the message itself (it may contain personal data)
    current_app.logger.info("chat request_id=%s length=%d", g.request_id, len(message))

    result = answer(message, current_app.config)
    body = {"response": result.text}
    if result.flags:
        body["security_flags"] = result.flags
    return jsonify(body)
