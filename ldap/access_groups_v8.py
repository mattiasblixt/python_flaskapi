'''
access_groups_v8
'''

import logging
import yaml
from flask import Blueprint, jsonify, g, request
from utils_v8 import ldap_auth_required, requires_endpoint_access, load_endpoint_permissions
from utils_v8 import LDAP_HOST
from ldap3 import Server, Connection, SUBTREE

access_groups_bp = Blueprint('access_groups', __name__)

# Configure logging
logging.basicConfig(
    filename='endpoint_permissions.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - User: %(user)s - Auth: %(auth_type)s - Action: %(action)s - Details: %(details)s'
)

@access_groups_bp.route('/access_groups', methods=['GET'])
@ldap_auth_required
@requires_endpoint_access
def list_access_groups():
    '''
    List all access groups and their permissions.

    Returns:
        tuple: JSON response with access groups data and HTTP status code
    '''
    endpoint_permissions = load_endpoint_permissions()
    groups = {}

    # Aggregate unique groups and their associated permissions
    for endpoint_method, group_dns in endpoint_permissions.items():
        for group_dn in group_dns:
            group_name = group_dn.split(',')[0].replace('cn=', '')
            if group_name not in groups:
                groups[group_name] = []
            groups[group_name].append(endpoint_method)

    return jsonify({
        'message': 'Access groups retrieved successfully',
        'groups': groups
    }), 200

@access_groups_bp.route('/access_groups/<group_name>', methods=['GET'])
@ldap_auth_required
@requires_endpoint_access
def get_access_group(group_name):
    '''
    Get details of a specific access group including permissions and users.

    Args:
        group_name: The name of the access group

    Returns:
        tuple: JSON response with group details and HTTP status code
    '''
    endpoint_permissions = load_endpoint_permissions()
    group_dn = f'cn={group_name},ou=groups,dc=example,dc=com'

    # Check if group exists in permissions
    permissions = [
        endpoint_method for endpoint_method, group_dns in endpoint_permissions.items()
        if group_dn in group_dns
    ]
    if not permissions:
        return jsonify({'message': f'Group {group_name} not found in permissions'}), 404

    # Get group members from LDAP
    try:
        server = Server(LDAP_HOST, get_info=ALL)
        conn = g.ldap_conn  # Reuse authenticated user's connection
        conn.search(
            search_base=group_dn,
            search_filter='(objectClass=group)',
            search_scope=SUBTREE,
            attributes=['member']
        )
        if len(conn.entries) != 1:
            return jsonify({'message': f'Group {group_name} not found in LDAP'}), 404

        members = conn.entries[0].member.values if conn.entries[0].member else []
        users = [member.split(',')[0].replace('cn=', '') for member in members]

        return jsonify({
            'message': f'Details for group {group_name}',
            'group_name': group_name,
            'permissions': permissions,
            'users': users
        }), 200

    except Exception as e:
        return jsonify({'message': 'Error retrieving group details', 'error': str(e)}), 500

@access_groups_bp.route('/access_groups', methods=['POST'])
@ldap_auth_required
@requires_endpoint_access
def create_access_group():
    '''
    Create a new access group via POST request.

    Returns:
        tuple: JSON response and HTTP status code
    '''
    data = request.get_json()
    if not data or 'group_name' not in data or 'permissions' not in data:
        return jsonify({'message': 'Missing group_name or permissions in request'}), 400

    group_name = data['group_name']
    permissions = data['permissions']  # List of endpoint/method keys, e.g., ["users/POST"]
    group_dn = f'cn={group_name},ou=groups,dc=example,dc=com'

    # Load current permissions
    endpoint_permissions = load_endpoint_permissions()

    # Check if group already exists in permissions
    for endpoint_method, group_dns in endpoint_permissions.items():
        if group_dn in group_dns:
            return jsonify({
                'message': f'Group {group_name} already exists in permissions'
            }), 400

    # Update permissions
    for endpoint_method in permissions:
        if endpoint_method not in endpoint_permissions:
            endpoint_permissions[endpoint_method] = []
        endpoint_permissions[endpoint_method].append(group_dn)

    # Save updated permissions to YAML
    try:
        with open('endpoint_permissions.yaml', 'w', encoding='utf-8') as file:
            yaml.safe_dump({'endpoint_permissions': endpoint_permissions}, file)

        # Log the change
        logging.info(
            '',
            extra={
                'user': g.username,
                'auth_type': g.auth_type,
                'action': 'CREATE_ACCESS_GROUP',
                'details': f'Created group {group_name} with permissions {permissions}'
            }
        )

        return jsonify({
            'message': f'Access group {group_name} created successfully',
            'permissions': permissions
        }), 201

    except Exception as e:
        return jsonify({'message': 'Error saving permissions', 'error': str(e)}), 500

@access_groups_bp.route('/access_groups/<group_name>', methods=['PUT'])
@ldap_auth_required
@requires_endpoint_access
def update_access_group(group_name):
    '''
    Update an access group's permissions via PUT request.

    Args:
        group_name: The name of the access group to update

    Returns:
        tuple: JSON response and HTTP status code
    '''
    data = request.get_json()
    if not data or 'permissions' not in data:
        return jsonify({'message': 'Missing permissions in request'}), 400

    new_permissions = data['permissions']  # List of endpoint/method keys
    group_dn = f'cn={group_name},ou=groups,dc=example,dc=com'

    # Load current permissions
    endpoint_permissions = load_endpoint_permissions()

    # Check if group exists
    group_exists = False
    old_permissions = []
    for endpoint_method, group_dns in endpoint_permissions.items():
        if group_dn in group_dns:
            group_exists = True
            old_permissions.append(endpoint_method)

    if not group_exists:
        return jsonify({'message': f'Group {group_name} not found in permissions'}), 404

    # Remove group from all current permissions
    for endpoint_method in old_permissions:
        endpoint_permissions[endpoint_method].remove(group_dn)
        if not endpoint_permissions[endpoint_method]:
            del endpoint_permissions[endpoint_method]

    # Add group to new permissions
    for endpoint_method in new_permissions:
        if endpoint_method not in endpoint_permissions:
            endpoint_permissions[endpoint_method] = []
        endpoint_permissions[endpoint_method].append(group_dn)

    # Save updated permissions to YAML
    try:
        with open('endpoint_permissions_v8.yml', 'w', encoding='utf-8') as file:
            yaml.safe_dump({'endpoint_permissions': endpoint_permissions}, file)

        # Log the change
        logging.info(
            '',
            extra={
                'user': g.username,
                'auth_type': g.auth_type,
                'action': 'UPDATE_ACCESS_GROUP',
                'details': f'Updated group {group_name}: Old permissions {old_permissions}, '
                           f'New permissions {new_permissions}'
            }
        )

        return jsonify({
            'message': f'Access group {group_name} updated successfully',
            'permissions': new_permissions
        }), 200

    except Exception as e:
        return jsonify({'message': 'Error saving permissions', 'error': str(e)}), 500
