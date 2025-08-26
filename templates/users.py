'''
Flask Blueprint for user-related API endpoints.
'''
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union
import secrets

from flask import Blueprint, jsonify, request
from utils import auth, user_store, logging, MAX_DAYS, PASSWORD_LENGTH, BASE_ENDPOINT

users_bp = Blueprint("users", __name__)


def check_permission(endpoint: str, method: str):
    '''
    Decorator to check if authenticated user has permission for the endpoint and method.
    '''
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


@users_bp.route("/users", methods=["POST"])
@auth.login_required
@check_permission(BASE_ENDPOINT, "POST")
def create_user() -> Tuple[Dict[str, str], int]:
    '''
    Create a new user via POST request.

    Returns:
        tuple: JSON response with password and HTTP status code
    '''
    data = request.get_json(silent=True)
    now = datetime.now()
    if not data:
        logging.error("Failed creation: No JSON provided by %s", auth.current_user())
        return jsonify({"error": "No JSON provided"}), 400

    username = data.get("username")
    owner = data.get("owner")
    access_groups = data.get("access_groups", ["consumers"])

    if not username:
        logging.error("Failed creation: Username is mandatory by %s", auth.current_user())
        return jsonify({"error": "Username is mandatory"}), 400

    if not owner:
        logging.error("Failed creation: Owner is mandatory by %s", auth.current_user())
        return jsonify({"error": "Owner is mandatory"}), 400

    if user_store.get_user(username):
        logging.error("Failed creation: Username already exists by %s", auth.current_user())
        return jsonify({"error": "Username already exists"}), 409

    for access_group in access_groups:
        if access_group not in user_store.access_groups:
            logging.error(
                "Failed creation: Invalid access group %s by %s",
                access_group,
                auth.current_user()
            )
            return jsonify({"error": f"Invalid access group: {access_group}"}), 400

    validity_str = data.get("validity")
    max_validity = now + timedelta(days=MAX_DAYS)

    if validity_str:
        try:
            validity = datetime.fromisoformat(validity_str)
            if validity > max_validity:
                logging.error(
                    "Failed creation: Validity exceeds 365 days in future by %s",
                    auth.current_user()
                )
                return jsonify({"error": "Validity exceeds 365 days in future"}), 400
        except ValueError:
            logging.error(
                "Failed creation: Invalid datetime format by %s",
                auth.current_user()
            )
            return jsonify({"error": "Invalid datetime format"}), 400
    else:
        validity = max_validity

    password = data.get("password")
    if password:
        if len(password) != PASSWORD_LENGTH:
            logging.error(
                "Failed creation: Password must be 16 characters long by %s",
                auth.current_user()
            )
            return jsonify({"error": "Password must be 16 characters long"}), 400
    else:
        password = secrets.token_urlsafe(12)  # Generates 16 characters

    user_store.add_user(username, password, owner, validity, access_groups)

    logging.info("Successful creation of user: %s by %s", username, auth.current_user())
    return jsonify({"password": password}), 201


@users_bp.route("/users", methods=["GET"])
@auth.login_required
@check_permission(BASE_ENDPOINT, "GET")
def list_users() -> Tuple[Union[List[Dict], Dict[str, str]], int]:
    '''
    List all users via GET request.

    Returns:
        tuple: JSON response with user data and HTTP status code
    '''
    now = datetime.now()
    perms = user_store.get_effective_permissions(auth.current_user())
    if "users/GET_ALL" in perms:
        result = []
        for username, info in user_store.get_all_users().items():
            days_until_expiry = max(0, (info["validity"] - now).days)
            result.append({
                "username": username,
                "owner": info["owner"],
                "expiry_date": info["validity"].isoformat(),
                "days_until_expiry": days_until_expiry,
                "access_groups": info["access_groups"]
            })
        return jsonify(result), 200
    if "users/GET_OWN" in perms:
        username = auth.current_user()
        info = user_store.get_user(username)
        if not info:
            logging.error("Failed list: User %s not found by %s", username, auth.current_user())
            return jsonify({"error": "User not found"}), 404
        days_until_expiry = max(0, (info["validity"] - now).days)
        result = [{
            "username": username,
            "owner": info["owner"],
            "expiry_date": info["validity"].isoformat(),
            "days_until_expiry": days_until_expiry,
            "access_groups": info["access_groups"]
        }]
        return jsonify(result), 200
    # Should not reach here
    return jsonify({"error": "Forbidden"}), 403


@users_bp.route("/users", methods=["PUT"])
@auth.login_required
@check_permission(BASE_ENDPOINT, "PUT")
def update_user() -> Tuple[Dict, int]:
    '''
    Update an existing user via PUT request.

    Returns:
        tuple: JSON response with updated data and HTTP status code
    '''
    data = request.get_json(silent=True)
    now = datetime.now()
    if not data:
        logging.error("Failed update: No JSON provided by %s", auth.current_user())
        return jsonify({"error": "No JSON provided"}), 400

    target_username = data.get("username")
    if not target_username:
        logging.error(
            "Failed update: Username to update is required by %s",
            auth.current_user()
        )
        return jsonify({"error": "Username to update is required"}), 400

    if not user_store.get_user(target_username):
        logging.error("Failed update: User does not exist by %s", auth.current_user())
        return jsonify({"error": "User does not exist"}), 404

    add_access_groups = data.get("add_access_groups", [])
    remove_access_groups = data.get("remove_access_groups", [])

    for access_group in add_access_groups:
        if access_group not in user_store.access_groups:
            logging.error(
                "Failed update: Invalid access group %s by %s",
                access_group,
                auth.current_user()
            )
            return jsonify({"error": f"Invalid access group: {access_group}"}), 400

    response = {}
    if data.get("update_credentials"):
        new_validity = now + timedelta(days=MAX_DAYS)
        new_password = secrets.token_urlsafe(12)  # Generate new 16-char password
        user_store.update_user(target_username, password=new_password, validity=new_validity)
        response.update({
            "new_password": new_password,
            "new_validity": new_validity.isoformat()
        })
    else:
        user_store.update_user(
            target_username,
            add_access_groups=add_access_groups,
            remove_access_groups=remove_access_groups
        )
        response.update({
            "updated_access_groups": user_store.get_user(target_username)["access_groups"]
        })

    logging.info(
        "Successful update of user: %s by %s",
        target_username,
        auth.current_user()
    )
    return jsonify(response), 200


@users_bp.route("/users", methods=["DELETE"])
@auth.login_required
@check_permission(BASE_ENDPOINT, "DELETE")
def delete_user() -> Tuple[str, int]:
    '''
    Delete a user via DELETE request.

    Returns:
        tuple: Empty response and HTTP status code
    '''
    data = request.get_json(silent=True)
    if not data:
        logging.error("Failed delete: No JSON provided by %s", auth.current_user())
        return jsonify({"error": "No JSON provided"}), 400

    target_username = data.get("username")
    if not target_username:
        logging.error(
            "Failed delete: Username to delete is required by %s",
            auth.current_user()
        )
        return jsonify({"error": "Username to delete is required"}), 400

    if not user_store.get_user(target_username):
        logging.error("Failed delete: User does not exist by %s", auth.current_user())
        return jsonify({"error": "User does not exist"}), 404

    user_store.delete_user(target_username)

    logging.info(
        "Successful delete of user: %s by %s",
        target_username,
        auth.current_user()
    )
    return "", 204


@users_bp.route("/users", methods=["PATCH"])
@auth.login_required
@check_permission(BASE_ENDPOINT, "PATCH")
def change_own_password() -> Tuple[Dict, int]:
    '''
    Change the logged-in user's password via PATCH request.

    Returns:
        tuple: JSON response and HTTP status code
    '''
    data = request.get_json(silent=True)
    if not data:
        logging.error("Failed password change: No JSON provided by %s", auth.current_user())
        return jsonify({"error": "No JSON provided"}), 400

    new_password = data.get("new_password")
    if not new_password:
        logging.error("Failed password change: New password is required by %s", auth.current_user())
        return jsonify({"error": "New password is required"}), 400

    if len(new_password) != PASSWORD_LENGTH:
        logging.error(
            "Failed password change: Password must be 16 characters long by %s",
            auth.current_user()
        )
        return jsonify({"error": "Password must be 16 characters long"}), 400

    username = auth.current_user()
    user_store.update_user(username, password=new_password)

    logging.info("Successful password change for user: %s", username)
    return jsonify({"message": "Password updated successfully"}), 200
