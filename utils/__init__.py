'''
core_v12.py

Core components for user management Flask API.

'''
import json
import sys
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Set

from flask_httpauth import HTTPBasicAuth

# Constants
USERS_FILE = "users.json"
PASSWORDS_FILE = "pass.json"
ACCESS_GROUPS_FILE = "access_groups.json"
LOG_FILE = "user_log.log"
MAX_DAYS = 365
PASSWORD_LENGTH = 16
BASE_ENDPOINT = "users"
ACCESS_GROUPS_ENDPOINT = "access_groups"

# Logging setup
logging.basicConfig(
    # filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)  # Outputs to terminal
    ]
)

# Authentication setup
auth = HTTPBasicAuth()


class UserStore:
    '''
    Manages user data storage and access control.
    '''

    def __init__(self) -> None:
        '''
        Initialize UserStore with empty user dictionary and load users.
        '''
        self.users: Dict[str, Dict] = {}
        self.access_groups: Dict[str, List[str]] = {}
        self.load_access_groups()
        self.load_users()

    def load_access_groups(self) -> None:
        '''
        Load access groups from access_groups.json file if it exists.
        '''
        if os.path.exists(ACCESS_GROUPS_FILE):
            with open(ACCESS_GROUPS_FILE, "r", encoding="utf-8") as file:
                self.access_groups = json.load(file)
        else:
            self.access_groups = {
                "super": [
                    "users/GET_ALL",
                    "users/POST",
                    "users/PUT",
                    "users/DELETE",
                    "access_groups/GET",
                    "access_groups/POST",
                    "access_groups/PUT",
                    "users/PATCH",
                ],
                "consumers": ["users/GET_OWN",
                              "users/PATCH",
                              ],
                "users/GET_ALL": ["users/GET_ALL",
                                  ],
                "users/POST": ["users/POST",
                               ],
                "users/PUT": ["users/PUT",
                              ],
                "users/DELETE": ["users/DELETE",
                                 ],
                "users/GET_OWN": ["users/GET_OWN",
                                  ],
                "access_groups/GET": ["access_groups/GET",
                                      ],
                "access_groups/POST": ["access_groups/POST",
                                       ],
                "access_groups/PUT": ["access_groups/PUT",
                                      ],
                "users/PATCH": ["users/PATCH",
                                ],
            }
            self.save_access_groups()

    def save_access_groups(self) -> None:
        '''
        Save access groups to access_groups.json file.
        '''
        with open(ACCESS_GROUPS_FILE, "w", encoding="utf-8") as file:
            json.dump(self.access_groups, file)

    def add_access_group(self, name: str, permissions: List[str]) -> None:
        '''
        Add a new access group.

        Args:
            name: The name of the access group
            permissions: List of permissions for the group

        Raises:
            ValueError: If the access group already exists
        '''
        if name in self.access_groups:
            raise ValueError("Access group already exists")
        self.access_groups[name] = permissions
        self.save_access_groups()

    def update_access_group(
        self,
        name: str,
        add_permissions: Optional[List[str]] = None,
        remove_permissions: Optional[List[str]] = None,
    ) -> None:
        '''
        Update an existing access group's permissions.

        Args:
            name: The name of the access group to update
            add_permissions: Permissions to add
            remove_permissions: Permissions to remove

        Raises:
            ValueError: If the access group does not exist
        '''
        if name not in self.access_groups:
            raise ValueError("Access group does not exist")
        if add_permissions:
            self.access_groups[name] = list(
                set(self.access_groups[name] + add_permissions)
            )
        if remove_permissions:
            self.access_groups[name] = [
                p for p in self.access_groups[name] if p not in remove_permissions
            ]
        self.save_access_groups()

    def get_access_groups(self) -> Dict[str, List[str]]:
        '''
        Get all access groups.

        Returns:
            dict: Dictionary of access groups and their permissions
        '''
        return self.access_groups

    def get_access_group(self, name: str) -> Optional[List[str]]:
        '''
        Get permissions for a specific access group.

        Args:
            name: The name of the access group

        Returns:
            list: List of permissions if found, None otherwise
        '''
        return self.access_groups.get(name)

    def get_users_in_group(self, name: str) -> List[str]:
        '''
        Get users belonging to a specific access group.

        Args:
            name: The name of the access group

        Returns:
            list: List of usernames in the group
        '''
        return [
            username
            for username, info in self.users.items()
            if name in info.get("access_groups", [])
        ]

    def load_users(self) -> None:
        '''
        Load user data from users.json file if it exists.
        '''
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, "r", encoding="utf-8") as file:
                data = json.load(file)
                for username, info in data.items():
                    self.users[username] = {
                        "owner": info["owner"],
                        "validity": datetime.fromisoformat(info["validity"]),
                        "access_groups": info.get("access_groups", ["consumers"])
                    }

    def save_users(self) -> None:
        '''
        Save user data to users.json file.
        '''
        data = {}
        for username, info in self.users.items():
            data[username] = {
                "owner": info["owner"],
                "validity": info["validity"].isoformat(),
                "access_groups": info["access_groups"]
            }
        with open(USERS_FILE, "w", encoding="utf-8") as file:
            json.dump(data, file)

    def manage_password(self, username: str, password: Optional[str] = None) -> Optional[str]:
        '''
        Manage user passwords in pass.json file.

        Args:
            username: The username whose password is managed
            password: The password to set; if None, retrieve the password

        Returns:
            str: The password if retrieving, None if setting or user not found
        '''
        passwords = {}
        if os.path.exists(PASSWORDS_FILE):
            with open(PASSWORDS_FILE, "r", encoding="utf-8") as file:
                passwords = json.load(file)

        if password is not None:
            passwords[username] = password
            with open(PASSWORDS_FILE, "w", encoding="utf-8") as file:
                json.dump(passwords, file)
            return None
        return passwords.get(username)

    def add_user(
        self,
        username: str,
        password: str,
        owner: str,
        validity: datetime,
        access_groups: Optional[List[str]] = None
    ) -> None:
        '''
        Add a new user to the store and save to file.

        Args:
            username: The username of the new user
            password: The password for the user
            owner: The owner of the user account
            validity: The validity date of the user account
            access_groups: List of access group names
        '''
        self.users[username] = {
            "owner": owner,
            "validity": validity,
            "access_groups": access_groups or ["consumers"]
        }
        self.save_users()
        self.manage_password(username, password)

    def update_user(
        self,
        username: str,
        password: Optional[str] = None,
        validity: Optional[datetime] = None,
        add_access_groups: Optional[List[str]] = None,
        remove_access_groups: Optional[List[str]] = None
    ) -> bool:
        '''
        Update an existing user's password, validity, or access groups.

        Args:
            username: The username to update
            password: The new password
            validity: The new validity date
            add_access_groups: Access groups to add
            remove_access_groups: Access groups to remove

        Returns:
            bool: True if update successful, False if user not found
        '''
        if username in self.users:
            if validity is not None:
                self.users[username]["validity"] = validity
            current = set(self.users[username].get("access_groups", []))
            if add_access_groups:
                current.update(add_access_groups)
            if remove_access_groups:
                current.difference_update(remove_access_groups)
            self.users[username]["access_groups"] = list(current)
            self.save_users()
            if password is not None:
                self.manage_password(username, password)
            return True
        return False

    def delete_user(self, username: str) -> bool:
        '''
        Delete a user from the store.

        Args:
            username: The username to delete

        Returns:
            bool: True if deletion successful, False if user not found
        '''
        if username in self.users:
            del self.users[username]
            self.save_users()
            passwords = {}
            if os.path.exists(PASSWORDS_FILE):
                with open(PASSWORDS_FILE, "r", encoding="utf-8") as file:
                    passwords = json.load(file)
            passwords.pop(username, None)
            with open(PASSWORDS_FILE, "w", encoding="utf-8") as file:
                json.dump(passwords, file)
            return True
        return False

    def get_user(self, username: str) -> Optional[Dict]:
        '''
        Get user data by username.

        Args:
            username: The username to retrieve

        Returns:
            dict: User data if found, None otherwise
        '''
        user = self.users.get(username)
        if user:
            password = self.manage_password(username)
            if password is not None:
                user = user.copy()
                user["password"] = password
        return user

    def get_all_users(self) -> Dict[str, Dict]:
        '''
        Get all users in the store.

        Returns:
            dict: Dictionary of all users
        '''
        users = {}
        for username, info in self.users.items():
            users[username] = info.copy()
            password = self.manage_password(username)
            if password is not None:
                users[username]["password"] = password
        return users

    def get_effective_permissions(self, username: str) -> Set[str]:
        '''
        Get the effective permissions for a user based on their access groups.

        Args:
            username: The username to check

        Returns:
            set: Set of effective permissions
        '''
        user = self.get_user(username)
        if not user:
            return set()
        perms = set()
        for group in user.get("access_groups", []):
            perms.update(self.access_groups.get(group, []))
        return perms

    def has_permission(self, username: str, endpoint: str, method: str) -> bool:
        '''
        Check if user has permission for the specified endpoint and method.

        Args:
            username: The username to check
            endpoint: The endpoint (e.g., 'users')
            method: The HTTP method (e.g., 'GET')

        Returns:
            bool: True if user has permission, False otherwise
        '''
        perms = self.get_effective_permissions(username)
        if method == "GET" and endpoint == "users":
            return "users/GET_ALL" in perms or "users/GET_OWN" in perms
        if method == "GET" and endpoint == "access_groups":
            return "access_groups/GET" in perms
        return f"{endpoint}/{method.upper()}" in perms


user_store = UserStore()


@auth.verify_password
def verify_password(username: str, password: str) -> Optional[str]:
    '''
    Verify user credentials for authentication.

    Args:
        username: The username to verify
        password: The password to verify

        Returns:
            str: Username if credentials valid, None otherwise
    '''
    user = user_store.get_user(username)
    if user and user["password"] == password:
        return username
    return None
