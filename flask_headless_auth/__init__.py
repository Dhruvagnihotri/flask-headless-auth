"""
Flask-Headless-Auth
~~~~~~~~~~~~~~~~~~~

Modern, headless authentication with RBAC for Flask APIs.

Basic usage:

    from flask import Flask
    from flask_headless_auth import AuthSvc

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SECRET_KEY'] = 'your-secret-key'
    app.config['JWT_SECRET_KEY'] = 'your-jwt-secret'
    
    auth = AuthSvc(app)
    
    if __name__ == '__main__':
        app.run()

RBAC usage:

    from flask_headless_auth import permission_required, role_required_authsvc
    from flask_jwt_extended import jwt_required
    
    @app.route('/api/patients')
    @jwt_required()
    @permission_required('patients.view')
    def get_patients():
        return jsonify(patients)

:copyright: (c) 2024 by Dhruv Agnihotri.
:license: MIT, see LICENSE for more details.
"""

from .core import AuthSvc
from .__version__ import __version__

# Export mixins for users to create custom models
from .mixins import (
    UserMixin, RoleMixin, PermissionMixin,
    TokenMixin, MFATokenMixin, PasswordResetTokenMixin,
    OAuthTokenMixin
)

# Export RBAC decorators for route protection
from .managers.rbac_manager import (
    permission_required,
    permissions_required,
    any_permission,
    role_required_authsvc,
    roles_required,
    RBACManager,
    PermissionChecker,
)

# Export Audit manager and decorator
from .managers.audit_manager import (
    AuditManager,
    AuditActions,
    audit_action,
)

# Export Hooks manager
from .managers.hooks_manager import HooksManager

# Export db for convenience
from .extensions import db

__all__ = [
    # Core
    'AuthSvc',
    'db',
    
    # Mixins
    'UserMixin',
    'RoleMixin',
    'PermissionMixin',
    'TokenMixin',
    'MFATokenMixin',
    'PasswordResetTokenMixin',
    'OAuthTokenMixin',
    
    # RBAC decorators
    'permission_required',
    'permissions_required',
    'any_permission',
    'role_required_authsvc',
    'roles_required',
    
    # RBAC managers
    'RBACManager',
    'PermissionChecker',
    
    # Audit & Session management
    'AuditManager',
    'AuditActions',
    'audit_action',
    
    # Hooks
    'HooksManager',
    
    # Version
    '__version__',
]
