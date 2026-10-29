"""
ThreatLens — Flask Backend Application Server
Serves the REST API for model inference, metrics telemetry, alert dispatch, and dataset exploration.
"""

import os
import sys
import logging
from flask import Flask, jsonify

# Ensure project root is available
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.routes.api import api_bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s]: %(message)s"
)
logger = logging.getLogger("ThreatLens.App")

def create_app():
    app = Flask(__name__)

    # Configure CORS manually or via flask_cors if present
    try:
        from flask_cors import CORS
        CORS(app, resources={r"/*": {"origins": "*"}})
        logger.info("Flask-CORS initialized successfully.")
    except ImportError:
        @app.after_request
        def add_cors_headers(response):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
            return response

    # Register API blueprint
    app.register_blueprint(api_bp, url_prefix="")

    @app.errorhandler(404)
    def handle_not_found(e):
        return jsonify({"error": "Resource endpoint not found"}), 404

    @app.errorhandler(500)
    def handle_internal_error(e):
        logger.exception("Internal server error")
        return jsonify({"error": "An unexpected internal server error occurred"}), 500

    return app

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", 5001))
    app = create_app()
    logger.info("ThreatLens Flask service starting on port %d...", port)
    app.run(host="0.0.0.0", port=port, debug=False)
