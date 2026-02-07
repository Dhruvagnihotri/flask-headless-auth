"""
flask_headless_auth.mixins.role
~~~~~~~~~~~~~~~~~~~~~~~~~~

Role and Permission model mixins for RBAC.
Provides extensible base classes for custom role/permission models.
"""

import re


class RoleMixin:
    """
    Mixin for Role model providing RBAC fields and methods.
    
    Usage with custom models:
        class Role(db.Model, RoleMixin):
            __tablename__ = 'my_roles'
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(80), unique=True, nullable=False)
            description = db.Column(db.String(255))
            display_name = db.Column(db.String(100))
            is_system = db.Column(db.Boolean, default=False)
            permissions = db.relationship('Permission', secondary=..., ...)
    """
    
    id = None       # Must be defined by implementing class
    name = None     # Must be defined by implementing class
    
    def has_permission(self, permission_name):
        """
        Check if this role has a specific permission.
        
        Args:
            permission_name: Permission name string (e.g., 'patients.view')
            
        Returns:
            bool: True if role has the permission
        """
        if not hasattr(self, 'permissions') or self.permissions is None:
            return False
        return any(p.name == permission_name for p in self.permissions)
    
    def has_any_permission(self, *permission_names):
        """
        Check if this role has any of the specified permissions.
        
        Args:
            *permission_names: Variable permission name strings
            
        Returns:
            bool: True if role has at least one of the permissions
        """
        if not hasattr(self, 'permissions') or self.permissions is None:
            return False
        user_perms = {p.name for p in self.permissions}
        return bool(user_perms & set(permission_names))
    
    def has_all_permissions(self, *permission_names):
        """
        Check if this role has all of the specified permissions.
        
        Args:
            *permission_names: Variable permission name strings
            
        Returns:
            bool: True if role has all of the permissions
        """
        if not hasattr(self, 'permissions') or self.permissions is None:
            return False
        user_perms = {p.name for p in self.permissions}
        return set(permission_names).issubset(user_perms)
    
    def get_permission_names(self):
        """
        Get a set of all permission names for this role.
        
        Returns:
            set: Set of permission name strings
        """
        if not hasattr(self, 'permissions') or self.permissions is None:
            return set()
        return {p.name for p in self.permissions}
    
    def to_dict(self):
        """Convert role to dictionary."""
        result = {
            'id': self.id,
            'name': self.name,
        }
        if hasattr(self, 'display_name'):
            result['display_name'] = self.display_name
        if hasattr(self, 'description'):
            result['description'] = self.description
        if hasattr(self, 'is_system'):
            result['is_system'] = self.is_system
        if hasattr(self, 'permissions'):
            result['permissions'] = [
                p.to_dict() if hasattr(p, 'to_dict') else {'name': p.name}
                for p in self.permissions
            ] if self.permissions else []
        if 'metadata' in self.__table__.columns and getattr(self, 'metadata', None):
            result['metadata'] = self.metadata
        if hasattr(self, 'created_at') and self.created_at:
            result['created_at'] = self.created_at.isoformat()
        if hasattr(self, 'updated_at') and self.updated_at:
            result['updated_at'] = self.updated_at.isoformat()
        return result
    
    def to_summary_dict(self):
        """Convert role to a summary dictionary (without permissions)."""
        result = {
            'id': self.id,
            'name': self.name,
        }
        if hasattr(self, 'display_name'):
            result['display_name'] = self.display_name
        if hasattr(self, 'description'):
            result['description'] = self.description
        if hasattr(self, 'is_system'):
            result['is_system'] = self.is_system
        return result
    
    def __repr__(self):
        return f'<Role {self.name}>'


class PermissionMixin:
    """
    Mixin for Permission model providing RBAC fields and methods.
    
    Usage with custom models:
        class Permission(db.Model, PermissionMixin):
            __tablename__ = 'my_permissions'
            id = db.Column(db.Integer, primary_key=True)
            name = db.Column(db.String(100), unique=True, nullable=False)
            description = db.Column(db.String(255))
            category = db.Column(db.String(50))
            resource = db.Column(db.String(100))
            action = db.Column(db.String(50))
    """
    
    # Permission name validation pattern: resource.action
    PERMISSION_NAME_PATTERN = re.compile(r'^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$')
    
    id = None       # Must be defined by implementing class
    name = None     # Must be defined by implementing class
    
    @staticmethod
    def validate_name(name):
        """
        Validate permission name follows 'resource.action' format.
        
        Args:
            name: Permission name to validate
            
        Returns:
            bool: True if valid
            
        Raises:
            ValueError: If name format is invalid
        """
        if not name or not isinstance(name, str):
            raise ValueError("Permission name must be a non-empty string")
        
        if not PermissionMixin.PERMISSION_NAME_PATTERN.match(name):
            raise ValueError(
                f"Invalid permission name '{name}'. "
                f"Must follow 'resource.action' format using lowercase letters, "
                f"numbers, and underscores. Examples: 'patients.view', 'billing.manage'"
            )
        return True
    
    @staticmethod
    def parse_name(name):
        """
        Parse permission name into resource and action parts.
        
        Args:
            name: Permission name (e.g., 'patients.view')
            
        Returns:
            tuple: (resource, action) e.g., ('patients', 'view')
        """
        if '.' in name:
            parts = name.split('.', 1)
            return parts[0], parts[1]
        return name, ''
    
    def get_resource(self):
        """Get the resource part of the permission name."""
        if hasattr(self, 'resource') and self.resource:
            return self.resource
        resource, _ = self.parse_name(self.name)
        return resource
    
    def get_action(self):
        """Get the action part of the permission name."""
        if hasattr(self, 'action') and self.action:
            return self.action
        _, action = self.parse_name(self.name)
        return action
    
    def to_dict(self):
        """Convert permission to dictionary."""
        result = {
            'id': self.id,
            'name': self.name,
        }
        if hasattr(self, 'display_name'):
            result['display_name'] = self.display_name
        if hasattr(self, 'description'):
            result['description'] = self.description
        if hasattr(self, 'category'):
            result['category'] = self.category
        if hasattr(self, 'resource'):
            result['resource'] = self.resource
        if hasattr(self, 'action'):
            result['action'] = self.action
        if hasattr(self, 'is_system'):
            result['is_system'] = self.is_system
        if 'metadata' in self.__table__.columns and getattr(self, 'metadata', None):
            result['metadata'] = self.metadata
        return result
    
    def __repr__(self):
        return f'<Permission {self.name}>'
