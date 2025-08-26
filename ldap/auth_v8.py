'''
'''
import secrets
import yaml
import logging
from datetime import datetime, timedelta
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPException
from utils_v8 import ldap_auth_required, requires_endpoint_access, load_api_tokens
from utils_v8 import LDAP_HOST, LDAP_USER_SEARCH_FILTER, LDAP_BASE_DN, SUBTREE

# pylint: disable=no-member
auth_bp = Blueprint('auth', __name__)

# Configure logging
logging.basicConfig(
    filename='endpoint_permissions.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - User: %(user)s - Auth: %(auth_type)s - Action: %(action)s - Details: %(details)s'
)

@auth_bp.route('/login', methods=['POST'])
def login():
    '''
    Authenticate user via LDAP and issue a JWT token.

    Returns:
        tuple: JSON response with JWT token and HTTP status code
    '''
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Missing username or password'}), 400

    username = data['username']
    password = data['password']

    try:
        # Connect to LDAP server
        server = Server(LDAP_HOST, get_info=ALL)
        conn = Connection(server, user=username, password=password, auto_bind=True)

        # Verify user exists
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=LDAP_USER_SEARCH_FILTER.format(username),
            search_scope=SUBTREE,
            attributes=['distinguishedName']
        )
        if len(conn.entries) != 1:
            return jsonify({'message': 'User not found'}), 401

        # Create JWT token
        access_token = create_access_token(identity=username)
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token
        }), 200

    except LDAPException as e:
        return jsonify({'message': 'Invalid credentials', 'error': str(e)}), 401
    finally:
        conn.unbind()

@auth_bp.route('/create_api_token', methods=['POST'])
@ldap_auth_required
@requires_endpoint_access
def create_api_token():
    '''
    Create a new API token for the authenticated user.

    Returns:
        tuple: JSON response with API token and HTTP status code
    '''
    # Generate secure token
    token = secrets.token_hex(32)

    # Load existing API tokens
    api_tokens = load_api_tokens()

    # Add new token
    api_tokens[token] = {
        'username': g.username,
        'created': datetime.now().isoformat()
    }

    # Save updated API tokens to YAML
    try:
        with open('api_tokens.yaml', 'w') as file:
            yaml.safe_dump({'api_tokens': api_tokens}, file)

        # Log the change
        logging.info(
            '',
            extra={
                'user': g.username,
                'auth_type': g.auth_type,
                'action': 'CREATE_API_TOKEN',
                'details': f'Created API token for user {g.username}'
            }
        )

        return jsonify({
            'message': 'API token created successfully',
            'api_token': token,
            'expires_in_days': 365
        }), 201

    except Exception as e:
        return jsonify({'message': 'Error saving API token', 'error': str(e)}), 500

@auth_bp.route('/api_token', methods=['GET'])
@ldap_auth_required
@requires_endpoint_access
def get_api_token_details():
    '''
    Get details of the user's API token or all tokens if user is in UserAdmins group.

    Returns:
        tuple: JSON response with token details and HTTP status code
    '''
    api_tokens = load_api_tokens()
    user_admin_group = 'cn=UserAdmins,ou=groups,dc=example,dc=com'

    # Log the query
    logging.info(
        '',
        extra={
            'user': g.username,
            'auth_type': g.auth_type,
            'action': 'GET_API_TOKEN_DETAILS',
            'details': f'Queried API token details'
        }
    )

    # Check if user is in UserAdmins group
    if user_admin_group in g.user_groups:
        # Return all active tokens with usernames and days until expiry
        active_tokens = []
        now = datetime.now()
        for token, info in api_tokens.items():
            created = datetime.fromisoformat(info['created'])
            days_left = (created + timedelta(days=365) - now).days
            if days_left > 0:  # Only include active (non-expired) tokens
                active_tokens.append({
                    'token': token,
                    'username': info['username'],
                    'days_until_expiry': days_left
                })

        return jsonify({
            'message': 'All active API tokens retrieved successfully',
            'tokens': active_tokens
        }), 200

    # For non-admins, find their token
    user_token = None
    days_left = 0
    for token, info in api_tokens.items():
        if info['username'] == g.username:
            created = datetime.fromisoformat(info['created'])
            days_left = (created + timedelta(days=365) - datetime.now()).days
            if days_left > 0:  # Only include active token
                user_token = token
                break

    if user_token:
        return jsonify({
            'message': 'API token details retrieved successfully',
            'api_token': user_token,
            'days_until_expiry': days_left
        }), 200
    else:
        return jsonify({
            'message': 'No active API token found for user'
        }), 404
