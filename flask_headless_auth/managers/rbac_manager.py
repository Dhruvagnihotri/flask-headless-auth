"""
flask_headless_auth.managers.rbac_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

RBAC business logic manager.
Handles CRUD operations for roles and permissions,
and runtime permission checking with optional caching.
"""

import re
import logging
from functools import wraps
from flask_jwt_extended import get_jwt
from flask import jsonify, current_app

from flask_headless_auth import extensions

logger = logging.getLogger(__name__)

# Permission name validation pattern
PERMISSION_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$')


# ---------------------------------------------------------------------------
# Permission Checker (runtime validation with optional caching)
# ---------------------------------------------------------------------------

class PermissionChecker:
    """
    Runtime permission checking engine.
    
    Checks whether a user's role includes the required permission(s)
    by querying the database (with optional cache layer).
    """
    
    def __init__(self, role_model=None, permission_model=None, cache=None):
        self._role_model = role_model
        self._permission_model = permission_model
        self._cache = cache
    
    @property
    def role_model(self):
        if self._role_model:
            return self._role_model
        # Lazy resolve from app extensions
        authsvc = current_app.extensions.get('authsvc')
        if authsvc:
            return authsvc.role_model
        return None
    
    @property
    def cache(self):
        if self._cache is not None:
            return self._cache
        authsvc = current_app.extensions.get('authsvc')
        if authsvc:
            return authsvc.cache
        return None
    
    def _cache_key(self, role_id):
        """Generate cache key for role permissions."""
        prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        return f"{prefix}_role_perms:{role_id}"
    
    def get_role_permissions(self, role_id):
        """
        Get all permission names for a role (with caching).
        
        Args:
            role_id: Role ID to look up
            
        Returns:
            set: Set of permission name strings
        """
        cache = self.cache
        cache_enabled = current_app.config.get('AUTHSVC_CACHE_PERMISSIONS', True)
        
        # Try cache first
        if cache_enabled and cache:
            cache_key = self._cache_key(role_id)
            cached = cache.get(cache_key)
            if cached is not None:
                return cached
        
        # Query database
        Role = self.role_model
        if not Role:
            logger.warning("Role model not available for permission check")
            return set()
        
        role = Role.query.get(role_id)
        if not role:
            return set()
        
        permissions = role.get_permission_names()
        
        # Store in cache
        if cache_enabled and cache:
            ttl = current_app.config.get('AUTHSVC_PERMISSION_CACHE_TTL', 300)
            cache.set(self._cache_key(role_id), permissions, timeout=ttl)
        
        return permissions
    
    def check_permission(self, role_id, permission_name):
        """
        Check if a role has a specific permission.
        
        Args:
            role_id: Role ID from JWT claims
            permission_name: Required permission string
            
        Returns:
            bool: True if role has the permission
        """
        if not role_id:
            return False
        permissions = self.get_role_permissions(role_id)
        return permission_name in permissions
    
    def check_permissions(self, role_id, permission_names, require_all=True):
        """
        Check if a role has multiple permissions.
        
        Args:
            role_id: Role ID from JWT claims
            permission_names: List/tuple of required permission strings
            require_all: If True, ALL permissions must be present. 
                        If False, ANY one is sufficient.
            
        Returns:
            bool: True if permission requirements are met
        """
        if not role_id:
            return False
        permissions = self.get_role_permissions(role_id)
        required = set(permission_names)
        
        if require_all:
            return required.issubset(permissions)
        else:
            return bool(required & permissions)
    
    def invalidate_cache(self, role_id=None):
        """
        Invalidate permission cache for a role or all roles.
        
        Args:
            role_id: Specific role to invalidate, or None for all
        """
        cache = self.cache
        if not cache:
            return
        
        if role_id:
            cache.delete(self._cache_key(role_id))
        else:
            # Can't easily clear all role caches without a key pattern
            # Individual invalidation is the safe approach
            pass


# Singleton checker instance (lazy initialization)
_checker = None


def _get_checker():
    """Get or create the singleton PermissionChecker."""
    global _checker
    if _checker is None:
        _checker = PermissionChecker()
    return _checker


# ---------------------------------------------------------------------------
# Decorators for route protection
# ---------------------------------------------------------------------------

def role_required_authsvc(required_role):
    """
    Decorator: Require user to have a specific role.
    
    Accepts role by name (string) or by ID (int).
    
    Usage:
        @role_required_authsvc('admin')
        def admin_route():
            pass
        
        @role_required_authsvc(1)
        def admin_route():
            pass
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role_id = claims.get('role')
            
            if user_role_id is None:
                return jsonify({"msg": "Access forbidden: no role assigned"}), 403
            
            # If required_role is an integer, compare directly with role_id
            if isinstance(required_role, int):
                if user_role_id != required_role:
                    return jsonify({"msg": "Access forbidden: insufficient role"}), 403
            else:
                # String comparison: look up role name from database
                checker = _get_checker()
                Role = checker.role_model
                if Role:
                    role = Role.query.get(user_role_id)
                    if not role or role.name != required_role:
                        return jsonify({"msg": "Access forbidden: insufficient role"}), 403
                else:
                    # Fallback: direct comparison (backwards compatible)
                    if user_role_id != required_role:
                        return jsonify({"msg": "Access forbidden: insufficient role"}), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def roles_required(*required_roles):
    """
    Decorator: Require user to have ANY of the specified roles.
    
    Usage:
        @roles_required('admin', 'provider')
        def provider_or_admin_route():
            pass
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role_id = claims.get('role')
            
            if user_role_id is None:
                return jsonify({"msg": "Access forbidden: no role assigned"}), 403
            
            checker = _get_checker()
            Role = checker.role_model
            
            if Role:
                role = Role.query.get(user_role_id)
                if not role:
                    return jsonify({"msg": "Access forbidden: invalid role"}), 403
                
                # Check if user's role name matches any of the required roles
                role_names = set()
                role_ids = set()
                for r in required_roles:
                    if isinstance(r, int):
                        role_ids.add(r)
                    else:
                        role_names.add(r)
                
                if role.name in role_names or role.id in role_ids:
                    return f(*args, **kwargs)
            
            return jsonify({"msg": "Access forbidden: insufficient role"}), 403
        return wrapper
    return decorator


def permission_required(required_permission):
    """
    Decorator: Require user to have a specific permission.
    
    This is the RECOMMENDED way to protect routes. Use permission names
    instead of role names for maximum flexibility.
    
    Usage:
        @app.route('/api/patients')
        @jwt_required()
        @permission_required('patients.view')
        def get_patients():
            return jsonify(patients)
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Check if RBAC is enabled
            if not current_app.config.get('AUTHSVC_ENABLE_RBAC', True):
                return f(*args, **kwargs)
            
            claims = get_jwt()
            role_id = claims.get('role')
            
            if role_id is None:
                return jsonify({
                    "msg": "Access forbidden: no role assigned"
                }), 403
            
            checker = _get_checker()
            
            if not checker.check_permission(role_id, required_permission):
                return jsonify({
                    "msg": f"Access forbidden: missing permission '{required_permission}'"
                }), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def permissions_required(*required_permissions):
    """
    Decorator: Require user to have ALL specified permissions.
    
    Usage:
        @permissions_required('patients.view', 'patients.edit')
        def edit_patient():
            pass
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_app.config.get('AUTHSVC_ENABLE_RBAC', True):
                return f(*args, **kwargs)
            
            claims = get_jwt()
            role_id = claims.get('role')
            
            if role_id is None:
                return jsonify({"msg": "Access forbidden: no role assigned"}), 403
            
            checker = _get_checker()
            
            if not checker.check_permissions(role_id, required_permissions, require_all=True):
                return jsonify({
                    "msg": f"Access forbidden: missing one or more required permissions"
                }), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


def any_permission(*required_permissions):
    """
    Decorator: Require user to have ANY ONE of the specified permissions.
    
    Usage:
        @any_permission('patients.view', 'patients.edit')
        def access_patient():
            pass
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_app.config.get('AUTHSVC_ENABLE_RBAC', True):
                return f(*args, **kwargs)
            
            claims = get_jwt()
            role_id = claims.get('role')
            
            if role_id is None:
                return jsonify({"msg": "Access forbidden: no role assigned"}), 403
            
            checker = _get_checker()
            
            if not checker.check_permissions(role_id, required_permissions, require_all=False):
                return jsonify({
                    "msg": f"Access forbidden: need one of {list(required_permissions)}"
                }), 403
            
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# RBACManager: CRUD operations for roles & permissions
# ---------------------------------------------------------------------------

class RBACManager:
    """
    Business logic manager for RBAC operations.
    
    Provides CRUD for roles and permissions, role-permission assignment,
    and user-role assignment. Used by the RBAC routes blueprint.
    """
    
    def __init__(self, role_model, permission_model, user_model, 
                 db_session=None, cache=None):
        self.Role = role_model
        self.Permission = permission_model
        self.User = user_model
        self._db_session = db_session
        self.cache = cache
        self.checker = PermissionChecker(
            role_model=role_model,
            permission_model=permission_model,
            cache=cache
        )
    
    @property
    def db(self):
        if self._db_session:
            return self._db_session
        return extensions.db or extensions.get_db()
    
    # ------- ROLE CRUD -------
    
    def list_roles(self, include_permissions=False):
        """List all roles."""
        roles = self.Role.query.order_by(self.Role.id).all()
        if include_permissions:
            return [r.to_dict() for r in roles]
        return [r.to_summary_dict() if hasattr(r, 'to_summary_dict') else r.to_dict() for r in roles]
    
    def get_role(self, role_id):
        """Get a single role by ID."""
        return self.Role.query.get(role_id)
    
    def get_role_by_name(self, name):
        """Get a single role by name."""
        return self.Role.query.filter_by(name=name).first()
    
    def create_role(self, data):
        """
        Create a new role.
        
        Args:
            data: dict with keys: name, display_name, description, 
                  is_system, permission_ids
                  
        Returns:
            Role instance
            
        Raises:
            ValueError: If validation fails
        """
        name = data.get('name', '').strip().lower()
        
        if not name:
            raise ValueError("Role name is required")
        
        # Validate name format (alphanumeric + underscore)
        if not re.match(r'^[a-z][a-z0-9_]*$', name):
            raise ValueError(
                "Role name must start with a letter and contain only "
                + "lowercase letters, numbers, and underscores"
            )
        
        # Check uniqueness
        if self.Role.query.filter_by(name=name).first():
            raise ValueError(f"Role '{name}' already exists")
        
        role = self.Role(
            name=name,
            display_name=data.get('display_name', name.replace('_', ' ').title()),
            description=data.get('description', ''),
            is_system=data.get('is_system', False),
        )
        
        # Assign permissions if provided
        permission_ids = data.get('permission_ids', [])
        if permission_ids:
            permissions = self.Permission.query.filter(
                self.Permission.id.in_(permission_ids)
            ).all()
            role.permissions = permissions
        
        self.db.session.add(role)
        self.db.session.commit()
        
        logger.info(f"Created role '{name}' with {len(permission_ids)} permissions")
        return role
    
    def update_role(self, role_id, data):
        """
        Update an existing role.
        
        Args:
            role_id: ID of role to update
            data: dict with fields to update
            
        Returns:
            Updated Role instance
            
        Raises:
            ValueError: If validation fails
        """
        role = self.Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        if role.is_system and data.get('name') and data['name'] != role.name:
            raise ValueError("Cannot rename a system role")
        
        if 'display_name' in data:
            role.display_name = data['display_name']
        if 'description' in data:
            role.description = data['description']
        
        self.db.session.commit()
        self.checker.invalidate_cache(role_id)
        
        logger.info(f"Updated role '{role.name}'")
        return role
    
    def delete_role(self, role_id, force=False):
        """
        Delete a role.
        
        Args:
            role_id: ID of role to delete
            force: If True, reassign users to default role before deleting
            
        Raises:
            ValueError: If role can't be deleted
        """
        role = self.Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        if role.is_system and not force:
            raise ValueError("Cannot delete a system role. Use force=True to override.")
        
        # Check for users with this role
        user_count = self.User.query.filter_by(role_id=role_id).count()
        if user_count > 0 and not force:
            raise ValueError(
                f"Cannot delete role '{role.name}': {user_count} users assigned. "
                + "Reassign users first or use force=True."
            )
        
        if user_count > 0 and force:
            # Set users' role_id to None
            self.User.query.filter_by(role_id=role_id).update({'role_id': None})
        
        # Clear permissions association
        role.permissions = []
        self.db.session.delete(role)
        self.db.session.commit()
        self.checker.invalidate_cache(role_id)
        
        logger.info(f"Deleted role '{role.name}'")
    
    def clone_role(self, source_role_id, new_name, new_description=None):
        """
        Clone an existing role with all its permissions.
        
        Args:
            source_role_id: ID of role to clone
            new_name: Name for the new role
            new_description: Description for new role (optional)
            
        Returns:
            New Role instance
        """
        source = self.Role.query.get(source_role_id)
        if not source:
            raise ValueError("Source role not found")
        
        permission_ids = [p.id for p in source.permissions]
        
        return self.create_role({
            'name': new_name,
            'display_name': new_name.replace('_', ' ').title(),
            'description': new_description or f"Cloned from {source.name}",
            'permission_ids': permission_ids,
        })
    
    # ------- PERMISSION CRUD -------
    
    def list_permissions(self, category=None, resource=None):
        """
        List permissions, optionally filtered.
        
        Args:
            category: Filter by category
            resource: Filter by resource
        """
        query = self.Permission.query.order_by(self.Permission.category, self.Permission.name)
        
        if category:
            query = query.filter_by(category=category)
        if resource:
            query = query.filter_by(resource=resource)
        
        return [p.to_dict() for p in query.all()]
    
    def get_permission(self, permission_id):
        """Get a single permission by ID."""
        return self.Permission.query.get(permission_id)
    
    def get_permission_by_name(self, name):
        """Get a single permission by name."""
        return self.Permission.query.filter_by(name=name).first()
    
    def create_permission(self, data):
        """
        Create a new permission.
        
        Args:
            data: dict with keys: name, display_name, description, category, is_system
            
        Returns:
            Permission instance
        """
        name = data.get('name', '').strip().lower()
        
        if not name:
            raise ValueError("Permission name is required")
        
        # Validate name format: resource.action
        if not PERMISSION_NAME_PATTERN.match(name):
            raise ValueError(
                f"Invalid permission name '{name}'. "
                + "Must follow 'resource.action' format (e.g., 'patients.view')"
            )
        
        if self.Permission.query.filter_by(name=name).first():
            raise ValueError(f"Permission '{name}' already exists")
        
        # Auto-extract resource and action from name
        resource, action = name.split('.', 1)
        
        permission = self.Permission(
            name=name,
            display_name=data.get('display_name', name.replace('.', ' ').replace('_', ' ').title()),
            description=data.get('description', ''),
            category=data.get('category', resource),
            resource=resource,
            action=action,
            is_system=data.get('is_system', False),
        )
        
        self.db.session.add(permission)
        self.db.session.commit()
        
        logger.info(f"Created permission '{name}'")
        return permission
    
    def update_permission(self, permission_id, data):
        """
        Update an existing permission.
        
        Args:
            permission_id: ID of permission to update
            data: dict with fields to update
        """
        perm = self.Permission.query.get(permission_id)
        if not perm:
            raise ValueError("Permission not found")
        
        if perm.is_system and data.get('name') and data['name'] != perm.name:
            raise ValueError("Cannot rename a system permission")
        
        if 'display_name' in data:
            perm.display_name = data['display_name']
        if 'description' in data:
            perm.description = data['description']
        if 'category' in data:
            perm.category = data['category']
        
        self.db.session.commit()
        
        # Invalidate all role caches since this permission may be in multiple roles
        # (Safe but broad invalidation)
        for role in perm.roles:
            self.checker.invalidate_cache(role.id)
        
        logger.info(f"Updated permission '{perm.name}'")
        return perm
    
    def delete_permission(self, permission_id, force=False):
        """
        Delete a permission.
        
        Args:
            permission_id: ID of permission to delete
            force: If True, removes permission from all roles first
        """
        perm = self.Permission.query.get(permission_id)
        if not perm:
            raise ValueError("Permission not found")
        
        if perm.is_system and not force:
            raise ValueError("Cannot delete a system permission. Use force=True to override.")
        
        # Invalidate caches for affected roles
        for role in perm.roles:
            self.checker.invalidate_cache(role.id)
        
        # Clear role associations
        perm.roles = []
        self.db.session.delete(perm)
        self.db.session.commit()
        
        logger.info(f"Deleted permission '{perm.name}'")
    
    def create_permissions_bulk(self, permissions_data):
        """
        Create multiple permissions at once. Skips existing ones.
        
        Args:
            permissions_data: List of dicts with name, description, category
            
        Returns:
            tuple: (created_count, skipped_count)
        """
        created = 0
        skipped = 0
        
        for data in permissions_data:
            name = data.get('name', '').strip().lower()
            if not name:
                skipped += 1
                continue
            
            existing = self.Permission.query.filter_by(name=name).first()
            if existing:
                skipped += 1
                continue
            
            try:
                self.create_permission(data)
                created += 1
            except ValueError:
                skipped += 1
        
        return created, skipped
    
    # ------- ROLE-PERMISSION ASSIGNMENT -------
    
    def assign_permissions_to_role(self, role_id, permission_ids):
        """
        Add permissions to a role (additive - doesn't remove existing).
        
        Args:
            role_id: Role ID
            permission_ids: List of permission IDs to add
        """
        role = self.Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        existing_perm_ids = {p.id for p in role.permissions}
        new_permissions = self.Permission.query.filter(
            self.Permission.id.in_(permission_ids),
            ~self.Permission.id.in_(existing_perm_ids)
        ).all()
        
        for perm in new_permissions:
            role.permissions.append(perm)
        
        self.db.session.commit()
        self.checker.invalidate_cache(role_id)
        
        return role
    
    def revoke_permissions_from_role(self, role_id, permission_ids):
        """
        Remove permissions from a role.
        
        Args:
            role_id: Role ID
            permission_ids: List of permission IDs to remove
        """
        role = self.Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        role.permissions = [
            p for p in role.permissions if p.id not in set(permission_ids)
        ]
        
        self.db.session.commit()
        self.checker.invalidate_cache(role_id)
        
        return role
    
    def sync_role_permissions(self, role_id, permission_ids):
        """
        Replace all permissions on a role with the given set.
        
        Args:
            role_id: Role ID
            permission_ids: Complete list of permission IDs for the role
        """
        role = self.Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        permissions = self.Permission.query.filter(
            self.Permission.id.in_(permission_ids)
        ).all()
        
        role.permissions = permissions
        self.db.session.commit()
        self.checker.invalidate_cache(role_id)
        
        return role
    
    # ------- USER-ROLE ASSIGNMENT -------
    
    def assign_role_to_user(self, user_id, role_id):
        """
        Assign a role to a user.
        
        Args:
            user_id: User ID
            role_id: Role ID to assign
        """
        user = self.User.query.get(user_id)
        if not user:
            raise ValueError("User not found")
        
        role = self.Role.query.get(role_id)
        if not role:
            raise ValueError("Role not found")
        
        user.role_id = role_id
        self.db.session.commit()
        
        logger.info(f"Assigned role '{role.name}' to user {user_id}")
        return user
    
    def revoke_role_from_user(self, user_id):
        """
        Remove role from a user (set role_id to None).
        
        Args:
            user_id: User ID
        """
        user = self.User.query.get(user_id)
        if not user:
            raise ValueError("User not found")
        
        old_role_id = user.role_id
        user.role_id = None
        self.db.session.commit()
        
        logger.info(f"Revoked role from user {user_id}")
        return user
    
    def get_users_by_role(self, role_id, page=1, per_page=20):
        """
        Get users assigned to a specific role (paginated).
        
        Args:
            role_id: Role ID to filter by
            page: Page number (1-indexed)
            per_page: Items per page
        """
        pagination = self.User.query.filter_by(role_id=role_id).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return {
            'users': [self._user_summary(u) for u in pagination.items],
            'total': pagination.total,
            'page': pagination.page,
            'pages': pagination.pages,
        }
    
    def get_user_role(self, user_id):
        """
        Get a user's role and permissions.
        
        Args:
            user_id: User ID
            
        Returns:
            dict with role and permissions info
        """
        user = self.User.query.get(user_id)
        if not user:
            raise ValueError("User not found")
        
        if not user.role_id:
            return {'role': None, 'permissions': []}
        
        role = self.Role.query.get(user.role_id)
        if not role:
            return {'role': None, 'permissions': []}
        
        return {
            'role': role.to_dict(),
            'permissions': [p.name for p in role.permissions],
        }
    
    # ------- BULK / EXPORT / IMPORT -------
    
    def export_config(self):
        """
        Export all roles and permissions as a dictionary.
        Useful for backup, migration, or seeding.
        
        Returns:
            dict with roles, permissions, and their mappings
        """
        roles = self.Role.query.all()
        permissions = self.Permission.query.all()
        
        return {
            'roles': [r.to_dict() for r in roles],
            'permissions': [p.to_dict() for p in permissions],
        }
    
    def import_config(self, data):
        """
        Import roles and permissions from a dictionary.
        Creates missing items, skips existing ones.
        
        Args:
            data: dict with 'roles' and 'permissions' keys
            
        Returns:
            dict with counts of created/skipped items
        """
        result = {
            'permissions_created': 0,
            'permissions_skipped': 0,
            'roles_created': 0,
            'roles_skipped': 0,
        }
        
        # Import permissions first
        for perm_data in data.get('permissions', []):
            existing = self.Permission.query.filter_by(name=perm_data['name']).first()
            if existing:
                result['permissions_skipped'] += 1
                continue
            try:
                self.create_permission(perm_data)
                result['permissions_created'] += 1
            except ValueError:
                result['permissions_skipped'] += 1
        
        # Import roles
        for role_data in data.get('roles', []):
            existing = self.Role.query.filter_by(name=role_data['name']).first()
            if existing:
                result['roles_skipped'] += 1
                continue
            
            # Resolve permission names to IDs
            perm_names = [p['name'] if isinstance(p, dict) else p 
                          for p in role_data.get('permissions', [])]
            perm_ids = []
            for name in perm_names:
                perm = self.Permission.query.filter_by(name=name).first()
                if perm:
                    perm_ids.append(perm.id)
            
            try:
                self.create_role({
                    'name': role_data['name'],
                    'display_name': role_data.get('display_name'),
                    'description': role_data.get('description', ''),
                    'is_system': role_data.get('is_system', False),
                    'permission_ids': perm_ids,
                })
                result['roles_created'] += 1
            except ValueError:
                result['roles_skipped'] += 1
        
        return result
    
    # ------- HELPERS -------
    
    def _user_summary(self, user):
        """Create a summary dict for a user (safe for API responses)."""
        summary = {
            'id': user.id,
            'email': user.email,
            'role_id': user.role_id,
        }
        if hasattr(user, 'first_name'):
            summary['first_name'] = user.first_name
        if hasattr(user, 'last_name'):
            summary['last_name'] = user.last_name
        if hasattr(user, 'is_active'):
            summary['is_active'] = user.is_active
        return summary
