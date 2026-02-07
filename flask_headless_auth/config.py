"""
flask_headless_auth.config
~~~~~~~~~~~~~~~~~~~~

Default configuration for Flask-AuthSvc.
"""

DEFAULT_CONFIG = {
    # Core settings
    'AUTHSVC_URL_PREFIX': '/api/auth',
    'AUTHSVC_TABLE_PREFIX': 'authsvc',
    
    # Features
    'AUTHSVC_ENABLE_OAUTH': True,
    'AUTHSVC_ENABLE_MFA': True,
    'AUTHSVC_ENABLE_RBAC': True,
    
    # RBAC settings
    'AUTHSVC_RBAC_URL_PREFIX': '/api/rbac',       # URL prefix for RBAC management routes
    'AUTHSVC_RBAC_ADMIN_ROLE': 'admin',             # Role name with full RBAC management access
    'AUTHSVC_RBAC_ADMIN_PERMISSION': 'rbac.admin',  # Permission for RBAC management access
    'AUTHSVC_CACHE_PERMISSIONS': True,               # Cache permission lookups for performance
    'AUTHSVC_PERMISSION_CACHE_TTL': 300,             # Cache TTL in seconds (5 min default)
    
    # Admin user-management (Clerk / Supabase pattern)
    'AUTHSVC_ENABLE_ADMIN': True,                    # Enable admin user-management routes
    'AUTHSVC_ADMIN_URL_PREFIX': '/api/admin',        # URL prefix for admin routes
    
    # Audit & Session Management (Supabase parity)
    'AUTHSVC_ENABLE_AUDIT': True,                    # Enable audit logging and session tracking
    'AUTHSVC_AUDIT_URL_PREFIX': '/api/audit',        # URL prefix for audit routes
    'AUTHSVC_SESSION_TIMEOUT_MINUTES': None,         # Session timeout (None = no timeout)
    'AUTHSVC_SINGLE_SESSION_PER_USER': False,        # Enforce single session per user (Supabase Pro feature)
    'AUTHSVC_SESSION_INACTIVITY_TIMEOUT': None,      # Inactivity timeout in minutes
    'AUTHSVC_MAX_LOGIN_ATTEMPTS': 5,                 # Max failed login attempts before blocking
    'AUTHSVC_LOGIN_ATTEMPT_WINDOW': 30,              # Time window for login attempts (minutes)
    
    # Token Delivery Configuration
    # Options: 'cookies_only' (most secure), 'body_only' (APIs), 'dual' (flexible)
    'AUTHSVC_TOKEN_DELIVERY': 'cookies_only',  # Industry standard: secure by default
    
    # JWT settings
    # Where backend ACCEPTS tokens FROM (not where it sends them)
    'JWT_TOKEN_LOCATION': ['cookies', 'headers'],  # Accept from both for flexibility
    'JWT_HEADER_NAME': 'Authorization',
    'JWT_HEADER_TYPE': 'Bearer',
    'JWT_ACCESS_TOKEN_EXPIRES': 900,  # 15 minutes (industry standard, not 1 hour)
    'JWT_REFRESH_TOKEN_EXPIRES': 2592000,  # 30 days
    'JWT_COOKIE_CSRF_PROTECT': False,  # Not needed with SameSite=Strict
    'JWT_COOKIE_SECURE': True,  # HTTPS only
    'JWT_COOKIE_HTTPONLY': True,  # XSS protection
    'JWT_COOKIE_SAMESITE': 'Strict',  # CSRF protection (industry standard)
    'JWT_BLACKLIST_ENABLED': True,
    
    # Security
    'AUTHSVC_FORCE_HTTPS': False,
    'AUTHSVC_CORS_ORIGINS': ['*'],
    'WTF_CSRF_ENABLED': False,
    
    # Cache
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 300,
    
    # Rate limiting
    'RATELIMIT_ENABLED': True,
    'RATELIMIT_DEFAULT': '50000 per day; 5000 per hour',
}

