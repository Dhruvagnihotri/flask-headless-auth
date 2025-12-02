"""
flask_headless_auth.models.role
~~~~~~~~~~~~~~~~~~~~~~~~~~

Role and Permission models for RBAC.
"""

from sqlalchemy.ext.declarative import declared_attr
from flask_headless_auth import extensions

# Import db from extensions - it will be set by core.py before models are imported
db = extensions.db or extensions.get_db()


class Role(db.Model):
    """Role model for role-based access control."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))
    
    # Many-to-many relationship with permissions
    @declared_attr
    def permissions(cls):
        """Dynamic permissions relationship."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        
        return db.relationship(
            'Permission',
            secondary=f'{prefix}_role_permissions',
            back_populates='roles',
            lazy='dynamic'
        )
    
    def to_dict(self):
        """Convert role to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'permissions': [p.name for p in self.permissions] if self.permissions else []
        }


class Permission(db.Model):
    """Permission model for RBAC."""
    
    @declared_attr
    def __tablename__(cls):
        """Generate table name based on app config."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        return f'{prefix}_permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255))
    
    # Many-to-many relationship with roles
    @declared_attr
    def roles(cls):
        """Dynamic roles relationship."""
        from flask import current_app
        try:
            prefix = current_app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc')
        except RuntimeError:
            prefix = 'authsvc'
        
        return db.relationship(
            'Role',
            secondary=f'{prefix}_role_permissions',
            back_populates='permissions',
            lazy='dynamic'
        )
    
    def to_dict(self):
        """Convert permission to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
        }


# Association table placeholder - will be set by core.py during initialization
role_permissions = None

