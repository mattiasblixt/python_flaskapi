'''
app_v12.py
Flask API for user management with role-based access control.
'''
from typing import Dict, Tuple

from flask import Flask, jsonify, request
from utils import auth, logging
from users_api_v12 import users_bp
from access_groups_api_v12 import access_groups_bp

app = Flask(__name__)

@auth.error_handler
def auth_error(status: int) -> Tuple[Dict[str, str], int]:
    '''
    Handle authentication errors.

    Args:
        status: HTTP status code for the error

    Returns:
        tuple: JSON response with error message and status code
    '''
    auth_header = request.authorization
    attempted_user = auth_header.username if auth_header else "unknown"
    data = request.get_json(silent=True)
    target_username = data.get("username", "unknown") if data else "unknown"
    operation = "update" if request.method in ["PUT", "PATCH"] else "delete"
    logging.error(
        "Failed %s for user %s by %s: Unauthorized",
        operation,
        target_username,
        attempted_user
    )
    return jsonify({"error": "Unauthorized"}), status


# Register blueprints
app.register_blueprint(users_bp)
app.register_blueprint(access_groups_bp)


if __name__ == "__main__":
    app.run(debug=True)
