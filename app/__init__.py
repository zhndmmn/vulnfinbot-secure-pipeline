"""Mini-VulnFinBot — a small AI financial assistant built to be tested by a security pipeline."""
import logging
import os
import uuid

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

# Hard limits for the chat API
MAX_MESSAGE_LENGTH = 1000          # characters in "message"
MAX_REQUEST_BYTES = 16 * 1024      # whole request body


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        MAX_MESSAGE_LENGTH=MAX_MESSAGE_LENGTH,
        JSON_SORT_KEYS=False,
        # Model backend: "mock" (default, deterministic) or "ollama" (real LLM)
        LLM_BACKEND=os.getenv("LLM_BACKEND", "mock"),
        OLLAMA_URL=os.getenv("OLLAMA_URL", "http://localhost:11434"),
        OLLAMA_MODEL=os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b"),
        # Simulated authenticated customer. In a real system this comes from the
        # login session — never from the request body or from the model.
        SESSION_ACCOUNT_ID=os.getenv("SESSION_ACCOUNT_ID", "A001"),
    )
    if config:
        app.config.update(config)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    from .routes import bp
    app.register_blueprint(bp)

    @app.before_request
    def _request_id():
        g.request_id = uuid.uuid4().hex[:12]

    @app.after_request
    def _security_headers(resp):
        # Fixes the usual OWASP ZAP baseline findings for an API
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        resp.headers["Server"] = "vulnfinbot"
        return resp

    @app.errorhandler(HTTPException)
    def _http_error(err: HTTPException):
        # Generic JSON errors: no stack traces, no framework details
        return jsonify({"error": err.name.lower().replace(" ", "_")}), err.code

    @app.errorhandler(Exception)
    def _unhandled(err: Exception):
        app.logger.error("unhandled error request_id=%s type=%s",
                         getattr(g, "request_id", "-"), type(err).__name__)
        return jsonify({"error": "internal_error"}), 500

    return app
