"""
flask_headless_auth.routes.rbac
~~~~~~~~~~~~~~~~~~~~~~~~~~

RBAC management API routes.
Provides REST endpoints for managing roles, permissions, and user-role assignments.
All management endpoints require admin access.
"""

import logging
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt, get_jwt_identity

from flask_headless_auth.managers.rbac_manager import (
    RBACManager,
    role_required_authsvc,
    permission_required,
)

logger = logging.getLogger(__name__)


def _audit_rbac(action, actor_id, metadata=None, target_user_id=None):
    """Fire-and-forget audit log for RBAC admin events."""
    try:
        authsvc = current_app.extensions.get('authsvc')
        if authsvc and hasattr(authsvc, 'audit_manager'):
            authsvc.audit_manager.log_event(
                action=action,
                user_id=actor_id,
                target_user_id=target_user_id,
                metadata=metadata or {},
            )
    except Exception:
        pass


def _fire_hook(hook_name, *args, **kwargs):
    """Fire-and-forget auth hook."""
    try:
        authsvc = current_app.extensions.get('authsvc')
        if authsvc and hasattr(authsvc, 'hooks'):
            return authsvc.hooks.fire(hook_name, *args, **kwargs)
    except Exception:
        pass
    return None


def resolve_role(data, rbac_manager):
    """
    Resolve a role from request data. Accepts either:
      - { "role": "doctor" }       → look up by name (preferred, human-readable)
      - { "role_id": 3 }           → look up by ID (legacy/internal)
      - { "role": "doctor", "role_id": 3 } → role_id takes precedence

    Returns:
        (role_object, None) on success
        (None, (error_dict, status_code)) on failure

    Industry pattern: Clerk, Auth0, and Supabase all accept role names.
    IDs are internal — frontends should never need them.
    """
    role_id = data.get('role_id')
    role_name = data.get('role')

    if not role_id and not role_name:
        return None, ({"error": "role or role_id is required"}, 400)

    if role_id:
        role = rbac_manager.get_role(role_id)
        if not role:
            return None, ({"error": f"Role with id {role_id} not found"}, 404)
        return role, None

    # Look up by name using rbac_manager's built-in method
    try:
        role = rbac_manager.get_role_by_name(role_name)
        if not role:
            return None, ({"error": f"Role '{role_name}' not found"}, 404)
        return role, None
    except Exception as e:
        logger.error(f"Error resolving role by name '{role_name}': {e}")
        return None, ({"error": "Failed to resolve role"}, 500)


def _is_admin(claims, rbac_manager):
    """
    Check if the current user has admin access for RBAC management.
    
    Admin access is granted if:
    1. User's role name matches AUTHSVC_RBAC_ADMIN_ROLE config
    2. User's role has the 'rbac.admin' permission (or configured permission)
    3. User's role has specific management permission for the operation
    """
    role_id = claims.get('role')
    if not role_id:
        return False
    
    admin_role_name = current_app.config.get('AUTHSVC_RBAC_ADMIN_ROLE', 'admin')
    admin_permission = current_app.config.get('AUTHSVC_RBAC_ADMIN_PERMISSION', 'rbac.admin')
    
    role = rbac_manager.get_role(role_id)
    if not role:
        return False
    
    # Check if user is admin by role name
    if role.name == admin_role_name:
        return True
    
    # Check if user has rbac.admin permission
    if role.has_permission(admin_permission):
        return True
    
    return False


def create_rbac_blueprint(role_model, permission_model, user_model,
                          cache=None, blueprint_name='authsvc_rbac'):
    """
    Create and return the RBAC management blueprint.
    
    Args:
        role_model: Role model class
        permission_model: Permission model class
        user_model: User model class
        cache: Optional cache instance
        blueprint_name: Name for the blueprint
        
    Returns:
        Flask Blueprint with RBAC management routes
    """
    rbac_bp = Blueprint(blueprint_name, __name__)
    
    rbac_manager = RBACManager(
        role_model=role_model,
        permission_model=permission_model,
        user_model=user_model,
        cache=cache,
    )
    
    # ==========================================================
    # ROLE MANAGEMENT ENDPOINTS
    # ==========================================================
    
    @rbac_bp.route('/roles', methods=['GET'])
    @jwt_required()
    def list_roles():
        """
        List all roles.
        
        Query params:
            include_permissions (bool): Include permissions in response
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        include_permissions = request.args.get('include_permissions', 'false').lower() == 'true'
        
        roles = rbac_manager.list_roles(include_permissions=include_permissions)
        return jsonify({"roles": roles}), 200
    
    @rbac_bp.route('/roles', methods=['POST'])
    @jwt_required()
    def create_role():
        """
        Create a new role.
        
        Body:
            name (str): Role name (lowercase, alphanumeric + underscore)
            display_name (str): Human-readable name (optional)
            description (str): Description (optional)
            permission_ids (list): List of permission IDs to assign (optional)
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        try:
            role = rbac_manager.create_role(data)
            _audit_rbac('rbac.role_created', claims.get('id'),
                        metadata={'role_name': role.name, 'role_id': role.id})
            return jsonify({
                "message": "Role created successfully",
                "role": role.to_dict()
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/roles/<int:role_id>', methods=['GET'])
    @jwt_required()
    def get_role(role_id):
        """Get a single role with its permissions."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        role = rbac_manager.get_role(role_id)
        if not role:
            return jsonify({"error": "Role not found"}), 404
        
        return jsonify({"role": role.to_dict()}), 200
    
    @rbac_bp.route('/roles/<int:role_id>', methods=['PUT'])
    @jwt_required()
    def update_role(role_id):
        """
        Update a role.
        
        Body:
            display_name (str): Updated display name
            description (str): Updated description
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        try:
            role = rbac_manager.update_role(role_id, data)
            return jsonify({
                "message": "Role updated successfully",
                "role": role.to_dict()
            }), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/roles/<int:role_id>', methods=['DELETE'])
    @jwt_required()
    def delete_role(role_id):
        """
        Delete a role.
        
        Query params:
            force (bool): Force delete even if users assigned or system role
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        force = request.args.get('force', 'false').lower() == 'true'
        
        try:
            role = rbac_manager.get_role(role_id)
            role_name = role.name if role else f'id:{role_id}'
            rbac_manager.delete_role(role_id, force=force)
            _audit_rbac('rbac.role_deleted', claims.get('id'),
                        metadata={'role_name': role_name, 'role_id': role_id, 'force': force})
            return jsonify({"message": "Role deleted successfully"}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/roles/<int:role_id>/clone', methods=['POST'])
    @jwt_required()
    def clone_role(role_id):
        """
        Clone a role with all its permissions.
        
        Body:
            name (str): Name for the new role
            description (str): Description for new role (optional)
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data or not data.get('name'):
            return jsonify({"error": "New role name is required"}), 400
        
        try:
            new_role = rbac_manager.clone_role(
                role_id, 
                new_name=data['name'],
                new_description=data.get('description')
            )
            return jsonify({
                "message": "Role cloned successfully",
                "role": new_role.to_dict()
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    # ==========================================================
    # ROLE-PERMISSION MANAGEMENT ENDPOINTS
    # ==========================================================
    
    @rbac_bp.route('/roles/<int:role_id>/permissions', methods=['GET'])
    @jwt_required()
    def get_role_permissions(role_id):
        """Get all permissions for a role."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        role = rbac_manager.get_role(role_id)
        if not role:
            return jsonify({"error": "Role not found"}), 404
        
        permissions = [p.to_dict() for p in role.permissions]
        return jsonify({"permissions": permissions}), 200
    
    @rbac_bp.route('/roles/<int:role_id>/permissions', methods=['PUT'])
    @jwt_required()
    def sync_role_permissions(role_id):
        """
        Replace ALL permissions on a role.
        
        Body:
            permission_ids (list): Complete list of permission IDs
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data or 'permission_ids' not in data:
            return jsonify({"error": "permission_ids list is required"}), 400
        
        try:
            role = rbac_manager.sync_role_permissions(role_id, data['permission_ids'])
            _audit_rbac('rbac.permission_changed', claims.get('id'),
                        metadata={'role_id': role_id, 'action': 'sync',
                                  'permission_ids': data['permission_ids']})
            return jsonify({
                "message": "Role permissions updated successfully",
                "role": role.to_dict()
            }), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
    @jwt_required()
    def add_role_permissions(role_id):
        """
        Add permissions to a role (additive).
        
        Body:
            permission_ids (list): Permission IDs to add
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data or 'permission_ids' not in data:
            return jsonify({"error": "permission_ids list is required"}), 400
        
        try:
            role = rbac_manager.assign_permissions_to_role(role_id, data['permission_ids'])
            return jsonify({
                "message": "Permissions added to role successfully",
                "role": role.to_dict()
            }), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/roles/<int:role_id>/permissions', methods=['DELETE'])
    @jwt_required()
    def remove_role_permissions(role_id):
        """
        Remove permissions from a role.
        
        Body:
            permission_ids (list): Permission IDs to remove
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data or 'permission_ids' not in data:
            return jsonify({"error": "permission_ids list is required"}), 400
        
        try:
            role = rbac_manager.revoke_permissions_from_role(role_id, data['permission_ids'])
            return jsonify({
                "message": "Permissions removed from role successfully",
                "role": role.to_dict()
            }), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    # ==========================================================
    # PERMISSION MANAGEMENT ENDPOINTS
    # ==========================================================
    
    @rbac_bp.route('/permissions', methods=['GET'])
    @jwt_required()
    def list_permissions():
        """
        List all permissions.
        
        Query params:
            category (str): Filter by category
            resource (str): Filter by resource
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        category = request.args.get('category')
        resource = request.args.get('resource')
        
        permissions = rbac_manager.list_permissions(
            category=category, resource=resource
        )
        return jsonify({"permissions": permissions}), 200
    
    @rbac_bp.route('/permissions', methods=['POST'])
    @jwt_required()
    def create_permission():
        """
        Create a new permission.
        
        Body:
            name (str): Permission name (format: resource.action)
            display_name (str): Human-readable name (optional)
            description (str): Description (optional)
            category (str): Grouping category (optional, defaults to resource)
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        try:
            permission = rbac_manager.create_permission(data)
            return jsonify({
                "message": "Permission created successfully",
                "permission": permission.to_dict()
            }), 201
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/permissions/<int:permission_id>', methods=['GET'])
    @jwt_required()
    def get_permission(permission_id):
        """Get a single permission."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        perm = rbac_manager.get_permission(permission_id)
        if not perm:
            return jsonify({"error": "Permission not found"}), 404
        
        return jsonify({"permission": perm.to_dict()}), 200
    
    @rbac_bp.route('/permissions/<int:permission_id>', methods=['PUT'])
    @jwt_required()
    def update_permission(permission_id):
        """Update a permission."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        try:
            perm = rbac_manager.update_permission(permission_id, data)
            return jsonify({
                "message": "Permission updated successfully",
                "permission": perm.to_dict()
            }), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/permissions/<int:permission_id>', methods=['DELETE'])
    @jwt_required()
    def delete_permission(permission_id):
        """Delete a permission."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        force = request.args.get('force', 'false').lower() == 'true'
        
        try:
            rbac_manager.delete_permission(permission_id, force=force)
            return jsonify({"message": "Permission deleted successfully"}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/permissions/bulk', methods=['POST'])
    @jwt_required()
    def create_permissions_bulk():
        """
        Create multiple permissions at once.
        
        Body:
            permissions (list): List of permission objects with name, description, category
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data or 'permissions' not in data:
            return jsonify({"error": "permissions list is required"}), 400
        
        created, skipped = rbac_manager.create_permissions_bulk(data['permissions'])
        return jsonify({
            "message": f"Created {created} permissions, skipped {skipped}",
            "created": created,
            "skipped": skipped
        }), 201
    
    # ==========================================================
    # USER-ROLE ASSIGNMENT ENDPOINTS
    # ==========================================================
    
    @rbac_bp.route('/users/<int:user_id>/role', methods=['GET'])
    @jwt_required()
    def get_user_role(user_id):
        """Get a user's role and permissions."""
        claims = get_jwt()
        # Allow users to view their own role, or admins to view anyone's
        current_user_id = claims.get('id')
        if current_user_id != user_id and not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Access denied"}), 403
        
        try:
            result = rbac_manager.get_user_role(user_id)
            return jsonify(result), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 404
    
    @rbac_bp.route('/users/<int:user_id>/role', methods=['PUT'])
    @jwt_required()
    def assign_user_role(user_id):
        """
        Assign a role to a user.
        
        Body (accepts either):
            role (str): Role name to assign (preferred — e.g. "doctor")
            role_id (int): Role ID to assign (legacy/internal)
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400

        role, err = resolve_role(data, rbac_manager)
        if err:
            return jsonify(err[0]), err[1]
        
        try:
            # --- before_role_assign hook (Supabase parity) ---
            try:
                _fire_hook('before_role_assign', user_id, role.id)
            except ValueError as exc:
                return jsonify({"error": str(exc)}), 400

            user = rbac_manager.assign_role_to_user(user_id, role.id)

            _audit_rbac('rbac.role_assigned', claims.get('id'),
                        target_user_id=user_id,
                        metadata={'role_id': role.id, 'role_name': role.name})

            # --- after_role_assign hook ---
            _fire_hook('after_role_assign', user_id, role.id)

            return jsonify({
                "message": "Role assigned successfully",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "role_id": user.role_id,
                    "role_name": role.name,
                }
            }), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/users/<int:user_id>/role', methods=['DELETE'])
    @jwt_required()
    def revoke_user_role(user_id):
        """Remove role from a user."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        try:
            rbac_manager.revoke_role_from_user(user_id)
            _audit_rbac('rbac.role_revoked', claims.get('id'),
                        target_user_id=user_id)
            return jsonify({"message": "Role revoked successfully"}), 200
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
    
    @rbac_bp.route('/users', methods=['GET'])
    @jwt_required()
    def list_users_by_role():
        """
        List users filtered by role.
        
        Query params:
            role_id (int): Filter by role ID
            page (int): Page number (default 1)
            per_page (int): Items per page (default 20)
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        role_id = request.args.get('role_id', type=int)
        if not role_id:
            return jsonify({"error": "role_id query parameter is required"}), 400
        
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 100)
        
        result = rbac_manager.get_users_by_role(role_id, page=page, per_page=per_page)
        return jsonify(result), 200
    
    # ==========================================================
    # CURRENT USER ENDPOINTS
    # ==========================================================
    
    @rbac_bp.route('/me', methods=['GET'])
    @jwt_required()
    def get_my_role():
        """
        Get current user's role and permissions.
        Used by the frontend to determine what the user can access.
        """
        claims = get_jwt()
        role_id = claims.get('role')
        
        if not role_id:
            return jsonify({
                "role": None,
                "permissions": []
            }), 200
        
        role = rbac_manager.get_role(role_id)
        if not role:
            return jsonify({
                "role": None,
                "permissions": []
            }), 200
        
        return jsonify({
            "role": role.to_dict(),
            "permissions": [p.name for p in role.permissions]
        }), 200
    
    @rbac_bp.route('/me/permissions', methods=['GET'])
    @jwt_required()
    def get_my_permissions():
        """
        Get current user's permission names as a flat list.
        Optimized endpoint for frontend permission checking.
        """
        claims = get_jwt()
        role_id = claims.get('role')
        
        if not role_id:
            return jsonify({"permissions": []}), 200
        
        role = rbac_manager.get_role(role_id)
        if not role:
            return jsonify({"permissions": []}), 200
        
        return jsonify({
            "permissions": [p.name for p in role.permissions]
        }), 200
    
    @rbac_bp.route('/me/check', methods=['POST'])
    @jwt_required()
    def check_my_permissions():
        """
        Batch check if current user has specific permissions.
        
        Body:
            permissions (list): List of permission names to check
            
        Returns:
            dict: { results: { 'patients.view': true, 'billing.manage': false } }
        """
        claims = get_jwt()
        role_id = claims.get('role')
        
        data = request.get_json()
        if not data or 'permissions' not in data:
            return jsonify({"error": "permissions list is required"}), 400
        
        requested_permissions = data['permissions']
        
        if not role_id:
            results = {p: False for p in requested_permissions}
            return jsonify({"results": results}), 200
        
        checker = rbac_manager.checker
        user_permissions = checker.get_role_permissions(role_id)
        
        results = {p: p in user_permissions for p in requested_permissions}
        return jsonify({"results": results}), 200
    
    # ==========================================================
    # IMPORT/EXPORT ENDPOINTS
    # ==========================================================
    
    @rbac_bp.route('/export', methods=['GET'])
    @jwt_required()
    def export_config():
        """Export all roles and permissions as JSON."""
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        config = rbac_manager.export_config()
        return jsonify(config), 200
    
    @rbac_bp.route('/import', methods=['POST'])
    @jwt_required()
    def import_config():
        """
        Import roles and permissions from JSON.
        
        Body:
            roles (list): Role definitions
            permissions (list): Permission definitions
        """
        claims = get_jwt()
        if not _is_admin(claims, rbac_manager):
            return jsonify({"error": "Admin access required"}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required"}), 400
        
        result = rbac_manager.import_config(data)
        return jsonify({
            "message": "Import completed",
            **result
        }), 200
    
    return rbac_bp
