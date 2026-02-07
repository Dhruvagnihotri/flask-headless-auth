"""
flask_headless_auth.managers
~~~~~~~~~~~~~~~~~~~~~~

Business logic managers for authentication, RBAC, and audit.
"""

from .auth_manager import AuthManager
from .user_manager import UserManager
from .token_manager import TokenManager
from .oauth_manager import OAuthManager
from .rbac_manager import (
    RBACManager,
    PermissionChecker,
    role_required_authsvc,
    roles_required,
    permission_required,
    permissions_required,
    any_permission,
)
from .audit_manager import (
    AuditManager,
    AuditActions,
    audit_action,
)
from .hooks_manager import HooksManager

__all__ = [
    # Auth managers
    'AuthManager',
    'UserManager',
    'TokenManager',
    'OAuthManager',
    # RBAC
    'RBACManager',
    'PermissionChecker',
    # RBAC Decorators
    'role_required_authsvc',
    'roles_required',
    'permission_required',
    'permissions_required',
    'any_permission',
    # Audit
    'AuditManager',
    'AuditActions',
    'audit_action',
    # Hooks
    'HooksManager',
]
