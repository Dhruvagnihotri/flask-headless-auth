"""
flask_headless_auth.mixins.role
~~~~~~~~~~~~~~~~~~~~~~~~~~

Role and Permission model mixins.
"""


class RoleMixin:
    """Mixin for Role model providing RBAC fields and methods."""
    
    id = None  # Must be defined by implementing class
    name = None  # Must be defined by implementing class
    
    def to_dict(self):
        """Convert role to dictionary."""
        result = {
            'id': self.id,
            'name': self.name,
        }
        if hasattr(self, 'description'):
            result['description'] = self.description
        if hasattr(self, 'permissions'):
            result['permissions'] = [p.name for p in self.permissions] if self.permissions else []
        return result
    
    def __repr__(self):
        return f'<Role {self.name}>'


class PermissionMixin:
    """Mixin for Permission model providing RBAC fields and methods."""
    
    id = None  # Must be defined by implementing class
    name = None  # Must be defined by implementing class
    
    def to_dict(self):
        """Convert permission to dictionary."""
        result = {
            'id': self.id,
            'name': self.name,
        }
        if hasattr(self, 'description'):
            result['description'] = self.description
        return result
    
    def __repr__(self):
        return f'<Permission {self.name}>'

