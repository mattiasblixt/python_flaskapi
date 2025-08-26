'''
Assumptions

The Flask API is running at http://localhost:5000.
The LDAP configuration in ldap_config.yaml is correctly set up with valid credentials.
The user has permissions to access the /users/POST endpoint (e.g., is in UserAdmins or SuperAdmins
group as defined in endpoint_permissions.yaml).
The requests module is installed (pip install requests).
'''
import requests
from requests.exceptions import RequestException

def authenticate_and_get_jwt(base_url, username, password):
    """
    Authenticate with the Flask API to obtain a JWT token.

    Args:
        base_url (str): The base URL of the API (e.g., http://localhost:5000).
        username (str): The LDAP username.
        password (str): The LDAP password.

    Returns:
        str: The JWT token if successful, None otherwise.
    """
    login_url = f"{base_url}/api/login"
    payload = {"username": username, "password": password}

    try:
        response = requests.post(login_url, json=payload, timeout=5)
        response.raise_for_status()  # Raise exception for 4xx/5xx status codes

        data = response.json()
        if "access_token" in data:
            return data["access_token"]
        else:
            print(f"Error: No access token in response: {data}")
            return None

    except RequestException as e:
        print(f"Error during authentication: {str(e)}")
        return None

def access_users_endpoint(base_url, jwt_token):
    """
    Access the /users endpoint using the provided JWT token.

    Args:
        base_url (str): The base URL of the API.
        jwt_token (str): The JWT token for authentication.

    Returns:
        dict: The JSON response from the API if successful, None otherwise.
    """
    users_url = f"{base_url}/api/users"
    headers = {"Authorization": f"Bearer {jwt_token}"}

    try:
        response = requests.post(users_url, headers=headers, timeout=5)
        response.raise_for_status()  # Raise exception for 4xx/5xx status codes
        return response.json()

    except RequestException as e:
        print(f"Error accessing users endpoint: {str(e)}")
        return None

def main():
    """Main function to demonstrate authentication and accessing the users endpoint."""
    # Configuration
    base_url = "http://localhost:5000"
    username = "your_username"  # Replace with valid LDAP username
    password = "your_password"  # Replace with valid LDAP password

    # Step 1: Authenticate and get JWT
    jwt_token = authenticate_and_get_jwt(base_url, username, password)
    if not jwt_token:
        print("Failed to obtain JWT token. Exiting.")
        return

    print(f"JWT Token: {jwt_token}")

    # Step 2: Access /users endpoint with JWT
    response = access_users_endpoint(base_url, jwt_token)
    if response:
        print(f"Users endpoint response: {response}")
    else:
        print("Failed to access users endpoint.")

if __name__ == "__main__":
    main()
