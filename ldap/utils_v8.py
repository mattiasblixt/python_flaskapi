import yaml
from datetime import datetime, timedelta
from flask import g, jsonify, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException
from functools import wraps

# Load LDAP configuration from YAML file
def load_ldap_config(config_file='ldap_config_v8.yml'):
    """Load LDAP configuration from a YAML file."""
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config['ldap']
    except FileNotFoundError:
        raise Exception(f"Configuration file {config_file} not found")
    except yaml.YAMLError as e:
        raise Exception(f"Error parsing YAML file: {str(e)}")
    except KeyError:
        raise Exception("LDAP configuration not found in YAML file")

# Load endpoint permissions from separate YAML file
def load_endpoint_permissions(config_file='endpoint_permissions_v8.yml'):
    """Load endpoint permissions from a YAML file."""
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config['endpoint_permissions']
    except FileNotFoundError:
        raise Exception(f"Configuration file {config_file} not found")
    except yaml.YAMLError as e:
        raise Exception(f"Error parsing YAML file: {str(e)}")
    except KeyError:
        raise Exception("Endpoint permissions not found in YAML file")

# Load API tokens from YAML file
def load_api_tokens(config_file='api_tokens.yaml'):
    """Load API tokens from a YAML file."""
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
        return config.get('api_tokens', {})
    except FileNotFoundError:
        return {}
    except yaml.YAMLError as e:
        raise Exception(f"Error parsing YAML file: {str(e)}")

# Load configurations
ldap_config = load_ldap_config()
endpoint_permissions = load_endpoint_permissions()

# Extract settings from YAML
LDAP_HOST = ldap_config['host']
LDAP_BASE_DN = ldap_config['base_dn']
LDAP_BIND_USER = ldap_config.get('bind_user')  # Optional
LDAP_BIND_PASSWORD = ldap_config.get('bind_password')  # Optional
LDAP_USER_SEARCH_FILTER = ldap_config['user_search_filter']
LDAP_GROUP_SEARCH_FILTER = ldap_config['group_search_filter']
ENDPOINT_PERMISSIONS = endpoint_permissions  # Loaded from separate YAML

# Middleware to handle JWT or API token-based authentication
def ldap_auth_required(f):
    """Decorator to enforce JWT or API token-based authentication and LDAP group retrieval."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'message': 'Authentication required'}), 401

        token = auth_header.split(' ')[1]

        try:
            # Try to verify as JWT
            verify_jwt_in_request()
            g.username = get_jwt_identity()
            g.auth_type = 'JWT'
        except Exception:
            # If not JWT, check as API token
            api_tokens = load_api_tokens()
            if token in api_tokens:
                info = api_tokens[token]
                created = datetime.fromisoformat(info['created'])
                if (datetime.now() - created) > timedelta(days=365):
                    return jsonify({'message': 'API token expired'}), 401
                g.username = info['username']
                g.auth_type = 'API_TOKEN'
            else:
                return jsonify({'message': 'Invalid token'}), 401

        try:
            # Connect to LDAP server using service account
            server = Server(LDAP_HOST, get_info=ALL)
            conn = Connection(
                server,
                user=LDAP_BIND_USER,
                password=LDAP_BIND_PASSWORD,
                auto_bind=True
            )

            # Get user's DN
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=LDAP_USER_SEARCH_FILTER.format(g.username),
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            if len(conn.entries) != 1:
                return jsonify({'message': 'User not found'}), 401
            g.user_dn = conn.entries[0].distinguishedName.value

            # Get user's groups
            conn.search(
                search_base=LDAP_BASE_DN,
                search_filter=LDAP_GROUP_SEARCH_FILTER.format(g.user_dn),
                search_scope=SUBTREE,
                attributes=['distinguishedName']
            )
            g.user_groups = [entry.distinguishedName.value for entry in conn.entries]

            g.ldap_conn = conn  # Store connection for reuse
            return f(*args, **kwargs)

        except LDAPException as e:
            return jsonify({'message': 'LDAP error', 'error': str(e)}), 500
        finally:
            if 'ldap_conn' in g:
                g.ldap_conn.unbind()

    return decorated

# Decorator for endpoint and method-based authorization
def requires_endpoint_access(f):
    """Decorator to enforce endpoint and method-based authorization."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_dn' not in g or 'user_groups' not in g:
            return jsonify({'message': 'Authentication required first'}), 401

        # Get the endpoint and method
        path = request.path.lstrip('/')
        endpoint = path.replace('api/', '', 1) if path.startswith('api/') else path
        method = request.method

        # Construct the endpoint/method key (e.g., users/POST)
        permission_key = f"{endpoint}/{method}"

        # Check if the endpoint/method is defined in permissions
        allowed_groups = ENDPOINT_PERMISSIONS.get(permission_key, [])
        if not allowed_groups:
            return jsonify({'message': f'No groups defined for {permission_key}'}), 403

        # Check if user is in any of the allowed groups
        if not any(group in g.user_groups for group in allowed_groups):
            return jsonify({
                'message': f'Unauthorized: Not in required group for {permission_key}'
            }), 403

        return f(*args, **kwargs)

    return decorated
