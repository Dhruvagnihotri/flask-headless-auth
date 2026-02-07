"""
flask_headless_auth.routes
~~~~~~~~~~~~~~~~~~~~

API routes for authentication, RBAC, audit, and admin management.
"""

from .auth import create_auth_blueprint
from .rbac import create_rbac_blueprint
from .audit import create_audit_blueprint
from .admin import create_admin_blueprint

__all__ = [
    'create_auth_blueprint',
    'create_rbac_blueprint',
    'create_audit_blueprint',
    'create_admin_blueprint',
]
