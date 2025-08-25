from flask import Blueprint, jsonify, g
from utils_v8 import ldap_auth_required, requires_endpoint_access

users_bp = Blueprint('users', __name__)

@users_bp.route('/users', methods=['POST'])
@ldap_auth_required
@requires_endpoint_access
def create_user():
    """Create a new user."""
    return jsonify({
        'message': f'Hello, {g.username}! You are authorized to POST to users.'
    }), 200

@users_bp.route('/users', methods=['PUT'])
@ldap_auth_required
@requires_endpoint_access
def update_user():
    """Update an existing user."""
    return jsonify({
        'message': f'Hello, {g.username}! You are authorized to PUT to users.'
    }), 200

@users_bp.route('/users', methods=['DELETE'])
@ldap_auth_required
@requires_endpoint_access
def delete_user():
    """Delete a user."""
    return jsonify({
        'message': f'Hello, {g.username}! You are authorized to DELETE to users.'
    }), 200

@users_bp.route('/users', methods=['PATCH'])
@ldap_auth_required
@requires_endpoint_access
def patch_user():
    """Partially update a user."""
    return jsonify({
        'message': f'Hello, {g.username}! You are authorized to PATCH to users.'
    }), 200