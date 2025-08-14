'''
prompt:
update the solution so it follows all PEP-8 best practices and passes a full pylint

Flask API for user management with role-based access control."""
'''
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Union

import secrets
from flask import Flask, jsonify, request
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
auth = HTTPBasicAuth()

# Constants
USERS_FILE = "users.json"
LOG_FILE = "user_log.log"
MAX_DAYS = 365
PASSWORD_LENGTH = 16

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)


class UserStore:
    """
    Manages user data storage and access control.
    """

    def __init__(self) -> None:
        """Initialize UserStore with empty user dictionary and load users."""
        self.users: Dict[str, Dict] = {}
        self.access_groups: Dict[str, List[str]] = {
            "super": ["users/GET_ALL", "users/POST", "users/PUT", "users/DELETE"],
            "consumers": ["users/GET_OWN"],
            "users/GET_ALL": ["users/GET_ALL"],
            "users/POST": ["users/POST"],
            "users/PUT": ["users/PUT"],
            "users/DELETE": ["users/DELETE"],
            "users/GET_OWN": ["users/GET_OWN"]
        }
        self.load_users()

    def load_users(self) -> None:
        """
        Load user data from users.json file if it exists.
        """
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
                for username, info in data.items():
                    self.users[username] = {
                        "password": info["password"],
                        "owner": info["owner"],
                        "validity": datetime.fromisoformat(info["validity"]),
                        "access_groups": info.get("access_groups", ["consumers"])
                    }

    def save_users(self) -> None:
        """
        Save user data to users.json file.
        """
        data = {}
        for username, info in self.users.items():
            data[username] = {
                "password": info["password"],
                "owner": info["owner"],
                "validity": info["validity"].isoformat(),
                "access_groups": info["access_groups"]
            }
        with open(USERS_FILE, "w", encoding="utf-8") as file:
            json.dump(data, file)

    def add_user(
        self,
        username: str,
        password: str,
        owner: str,
        validity: datetime,
        access_groups: Optional[List[str]] = None
    ) -> None:
        """
        Add a new user to the store and save to file.

        Args:
            username: The username of the new user
            password: The password for the user
            owner: The owner of the user account
            validity: The validity date of the user account
            access_groups: List of access group names
        """
        self.users[username] = {
            "password": password,
            "owner": owner,
            "validity": validity,
            "access_groups": access_groups or ["consumers"]
        }
        self.save_users()

    def update_user(
        self,
        username: str,
        password: Optional[str] = None,
        validity: Optional[datetime] = None,
        add_access_groups: Optional[List[str]] = None,
        remove_access_groups: Optional[List[str]] = None
    ) -> bool:
        """
        Update an existing user's password, validity, or access groups.

        Args:
            username: The username to update
            password: The new password
            validity: The new validity date
            add_access_groups: Access groups to add
            remove_access_groups: Access groups to remove

        Returns:
            bool: True if update successful, False if user not found
        """
        if username in self.users:
            if password is not None:
                self.users[username]["password"] = password
            if validity is not None:
                self.users[username]["validity"] = validity
            current = set(self.users[username].get("access_groups", []))
            if add_access_groups:
                current.update(add_access_groups)
            if remove_access_groups:
                current.difference_update(remove_access_groups)
            self.users[username]["access_groups"] = list(current)
            self.save_users()
            return True
        return False

    def delete_user(self, username: str) -> bool:
        """
        Delete a user from the store.

        Args:
            username: The username to delete

        Returns:
            bool: True if deletion successful, False if user not found
        """
        if username in self.users:
            del self.users[username]
            self.save_users()
            return True
        return False

    def get_user(self, username: str) -> Optional[Dict]:
        """
        Get user data by username.

        Args:
            username: The username to retrieve

        Returns:
            dict: User data if found, None otherwise
        """
        return self.users.get(username)

    def get_all_users(self) -> Dict[str, Dict]:
        """
        Get all users in the store.

        Returns:
            dict: Dictionary of all users
        """
        return self.users

    def get_effective_permissions(self, username: str) -> Set[str]:
        """
        Get the effective permissions for a user based on their access groups.

        Args:
            username: The username to check

        Returns:
            set: Set of effective permissions
        """
        user = self.get_user(username)
        if not user:
            return set()
        perms = set()
        for group in user.get("access_groups", []):
            perms.update(self.access_groups.get(group, []))
        return perms

    def has_permission(self, username: str, endpoint: str, method: str) -> bool:
        """
        Check if user has permission for the specified endpoint and method.

        Args:
            username: The username to check
            endpoint: The endpoint (e.g., 'users')
            method: The HTTP method (e.g., 'GET')

        Returns:
            bool: True if user has permission, False otherwise
        """
        perms = self.get_effective_permissions(username)
        if method == "GET":
            return "users/GET_ALL" in perms or "users/GET_OWN" in perms
        return f"{endpoint}/{method.upper()}" in perms


user_store = UserStore()


@auth.verify_password
def verify_password(username: str, password: str) -> Optional[str]:
    """
    Verify user credentials for authentication.

    Args:
        username: The username to verify
        password: The password to verify

    Returns:
        str: Username if credentials valid, None otherwise
    """
    user = user_store.get_user(username)
    if user and user["password"] == password:
        return username
    return None


@auth.error_handler
def auth_error(status: int) -> Tuple[Dict[str, str], int]:
    """
    Handle authentication errors.

    Args:
        status: HTTP status code for the error

    Returns:
        tuple: JSON response with error message and status code
    """
    auth_header = request.authorization
    attempted_user = auth_header.username if auth_header else "unknown"
    data = request.get_json(silent=True)
    target_username = data.get("username", "unknown") if data else "unknown"
    operation = "update" if request.method == "PUT" else "delete"
    logging.error(
        "Failed %s for user %s by %s: Unauthorized",
        operation,
        target_username,
        attempted_user
    )
    return jsonify({"error": "Unauthorized"}), status


def check_permission(endpoint: str, method: str):
    """
    Decorator to check if authenticated user has permission for the endpoint and method.
    """
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


@app.route("/users", methods=["POST"])
@auth.login_required
@check_permission("users", "POST")
def create_user() -> Tuple[Dict[str, str], int]:
    """
    Create a new user via POST request.

    Returns:
        tuple: JSON response with password and HTTP status code
    """
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


@app.route("/users", methods=["GET"])
@auth.login_required
@check_permission("users", "GET")
def list_users() -> Tuple[Union[List[Dict], Dict[str, str]], int]:
    """
    List all users via GET request.

    Returns:
        tuple: JSON response with user data and HTTP status code
    """
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


@app.route("/users", methods=["PUT"])
@auth.login_required
@check_permission("users", "PUT")
def update_user() -> Tuple[Dict, int]:
    """
    Update an existing user via PUT request.

    Returns:
        tuple: JSON response with updated data and HTTP status code
    """
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


@app.route("/users", methods=["DELETE"])
@auth.login_required
@check_permission("users", "DELETE")
def delete_user() -> Tuple[str, int]:
    """
    Delete a user via DELETE request.

    Returns:
        tuple: Empty response and HTTP status code
    """
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


if __name__ == "__main__":
    app.run(debug=True)
