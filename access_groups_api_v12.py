'''
access_groups_api_v12
Flask Blueprint for access group-related API endpoints.
'''

from typing import Dict, List, Tuple

from flask import Blueprint, jsonify, request
from core_v12 import auth, user_store, logging, ACCESS_GROUPS_ENDPOINT

access_groups_bp = Blueprint("access_groups", __name__)


def check_permission(endpoint: str, method: str):
    """Decorator to check if authenticated user has permission for the endpoint and method."""
    def decorator(func):
        def wrapped(*args, **kwargs):
            if not auth.current_user():
                logging.error("Failed %s %s: No authenticated user", method, endpoint)
                return jsonify({"error": "Authentication required"}), 401
            if not user_store.has_permission(auth.current_user(), endpoint, method):
                logging.error(
                    "Failed %s %s: User %s lacks permission",
                    method,
                    endpoint,
                    auth.current_user()
                )
                return jsonify({"error": "Forbidden: Insufficient permissions"}), 403
            return func(*args, **kwargs)
        wrapped.__name__ = func.__name__  # Preserve function name for Flask
        return wrapped
    return decorator


@access_groups_bp.route("/access_groups", methods=["GET"])
@auth.login_required
@check_permission(ACCESS_GROUPS_ENDPOINT, "GET")
def list_access_groups() -> Tuple[List[Dict], int]:
    """List all access groups and their permissions.

    Returns:
        tuple: JSON response with access groups data and HTTP status code
    """
    groups = user_store.get_access_groups()
    result = [{"name": name, "permissions": perms} for name, perms in groups.items()]
    return jsonify(result), 200


@access_groups_bp.route("/access_groups/<group_name>", methods=["GET"])
@auth.login_required
@check_permission(ACCESS_GROUPS_ENDPOINT, "GET")
def get_access_group_details(group_name: str) -> Tuple[Dict, int]:
    """Get details of a specific access group including permissions and users.

    Args:
        group_name: The name of the access group

    Returns:
        tuple: JSON response with group details and HTTP status code
    """
    perms = user_store.get_access_group(group_name)
    if perms is None:
        logging.error(
            "Failed access group details: Group %s not found by %s",
            group_name,
            auth.current_user()
        )
        return jsonify({"error": "Access group not found"}), 404
    users = user_store.get_users_in_group(group_name)
    return jsonify({"permissions": perms, "users": users}), 200


@access_groups_bp.route("/access_groups", methods=["POST"])
@auth.login_required
@check_permission(ACCESS_GROUPS_ENDPOINT, "POST")
def create_access_group() -> Tuple[Dict, int]:
    """Create a new access group via POST request.

    Returns:
        tuple: JSON response and HTTP status code
    """
    data = request.get_json(silent=True)
    if not data:
        logging.error("Failed access group creation: No JSON provided by %s", auth.current_user())
        return jsonify({"error": "No JSON provided"}), 400

    name = data.get("name")
    permissions = data.get("permissions", [])

    if not name:
        logging.error("Failed access group creation: Name is mandatory by %s", auth.current_user())
        return jsonify({"error": "Name is mandatory"}), 400

    try:
        user_store.add_access_group(name, permissions)
    except ValueError as e:
        logging.error("Failed access group creation: %s by %s", str(e), auth.current_user())
        return jsonify({"error": str(e)}), 409

    logging.info("Successful creation of access group: %s by %s", name, auth.current_user())
    return jsonify({"message": "Access group created"}), 201


@access_groups_bp.route("/access_groups/<group_name>", methods=["PUT"])
@auth.login_required
@check_permission(ACCESS_GROUPS_ENDPOINT, "PUT")
def update_access_group_details(group_name: str) -> Tuple[Dict, int]:
    """Update an access group's permissions via PUT request.

    Args:
        group_name: The name of the access group to update

    Returns:
        tuple: JSON response and HTTP status code
    """
    data = request.get_json(silent=True)
    if not data:
        logging.error("Failed access group update: No JSON provided by %s", auth.current_user())
        return jsonify({"error": "No JSON provided"}), 400

    add_permissions = data.get("add_permissions", [])
    remove_permissions = data.get("remove_permissions", [])

    if not add_permissions and not remove_permissions:
        logging.error("Failed access group update: No updates provided by %s", auth.current_user())
        return jsonify({"error": "No updates provided"}), 400

    try:
        user_store.update_access_group(group_name, add_permissions, remove_permissions)
    except ValueError as e:
        logging.error("Failed access group update: %s by %s", str(e), auth.current_user())
        return jsonify({"error": str(e)}), 404

    logging.info("Successful update of access group: %s by %s", group_name, auth.current_user())
    return jsonify({"message": "Access group updated"}), 200
