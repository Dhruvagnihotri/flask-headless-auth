"""
flask_headless_auth.core
~~~~~~~~~~~~~~~~~~

Main AuthSvc extension class.
"""

from flask import Flask
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class AuthSvc:
    """
    Main Flask-AuthSvc extension.
    
    Usage:
        app = Flask(__name__)
        auth = AuthSvc(app)
        
    Or with app factory:
        auth = AuthSvc()
        auth.init_app(app)
    """
    
    def __init__(self, app: Optional[Flask] = None, 
                 user_model=None, role_model=None, permission_model=None,
                 blacklisted_token_model=None, mfa_token_model=None,
                 password_reset_token_model=None, user_activity_log_model=None,
                 oauth_token_model=None,
                 # New audit models
                 audit_log_model=None, user_session_model=None, activity_log_model=None,
                 post_login_redirect_url=None,
                 url_prefix: Optional[str] = None,
                 blueprint_name: Optional[str] = None,
                 cache_key_prefix: Optional[str] = None,
                 **kwargs):
        """
        Initialize the extension.
        
        Args:
            app: Flask application instance (optional)
            user_model: Custom User model class (optional, uses default if not provided)
            role_model: Custom Role model class (optional, uses default if not provided)
            permission_model: Custom Permission model class (optional, uses default if not provided)
            blacklisted_token_model: Custom BlacklistedToken model (optional)
            mfa_token_model: Custom MFAToken model (optional)
            password_reset_token_model: Custom PasswordResetToken model (optional)
            user_activity_log_model: Custom UserActivityLog model (optional)
            oauth_token_model: Custom OAuthToken model (optional)
            post_login_redirect_url: Default frontend URL for OAuth redirects (optional)
            url_prefix: URL prefix for routes (default: from config or '/api/auth')
            blueprint_name: Unique blueprint name (default: auto-generated from user table)
            cache_key_prefix: Prefix for cache keys (default: 'user_'). 
                              Use app-specific prefix in monorepo: 'brakit_user_', 'pdfwhiz_user_'
            **kwargs: Additional configuration options
        """
        self.app = None
        self.db = None
        self.jwt = None
        self.cache = None
        self.limiter = None
        
        # Auth lifecycle hooks (Supabase Auth Hooks parity)
        from flask_headless_auth.managers.hooks_manager import HooksManager
        self.hooks = HooksManager()
        
        # Store model classes (will be set to defaults if None)
        self.user_model = user_model
        self.role_model = role_model
        self.permission_model = permission_model
        self.blacklisted_token_model = blacklisted_token_model
        self.mfa_token_model = mfa_token_model
        self.password_reset_token_model = password_reset_token_model
        self.user_activity_log_model = user_activity_log_model
        self.oauth_token_model = oauth_token_model
        
        # Audit models (new for enterprise features)
        self.audit_log_model = audit_log_model
        self.user_session_model = user_session_model
        self.activity_log_model = activity_log_model
        
        # Store OAuth configuration
        self.post_login_redirect_url = post_login_redirect_url
        
        # Store URL prefix and blueprint name (instance-level, not config-dependent)
        self.url_prefix = url_prefix
        self.blueprint_name = blueprint_name
        
        # Cache key prefix for monorepo support (avoids key collision between apps)
        self.cache_key_prefix = cache_key_prefix or "user_"
        
        if app is not None:
            self.init_app(app, **kwargs)
    
    def init_app(self, app: Flask, **kwargs):
        """
        Initialize the extension with Flask app.
        
        Args:
            app: Flask application instance
            **kwargs: Additional configuration options (url_prefix, blueprint_name, etc.)
        """
        self.app = app
        
        # Allow overriding url_prefix and blueprint_name via init_app (app factory pattern)
        if 'url_prefix' in kwargs and not self.url_prefix:
            self.url_prefix = kwargs['url_prefix']
        if 'blueprint_name' in kwargs and not self.blueprint_name:
            self.blueprint_name = kwargs['blueprint_name']
        
        # Load default configuration
        self._load_config(app)
        
        # Track which models are custom vs default
        self._custom_models = {
            'user': self.user_model is not None,
            'role': self.role_model is not None,
        }
        
        # Initialize components
        self._init_database(app)
        self._init_jwt(app)
        self._init_cache_detection(app)  # Detect cache if available
        self._init_limiter(app)
        self._init_cors(app)
        self._init_security(app)
        self._init_email(app)
        self._init_oauth(app, **kwargs)
        self._init_routes(app)
        
        # Store in app.extensions
        if not hasattr(app, 'extensions'):
            app.extensions = {}
        app.extensions['authsvc'] = self
        
        logger.info("Flask-AuthSvc initialized successfully")
    
    def _load_config(self, app):
        """Load default configuration."""
        from flask_headless_auth.config import DEFAULT_CONFIG
        
        # Set defaults (don't override existing config)
        for key, value in DEFAULT_CONFIG.items():
            app.config.setdefault(key, value)
    
    def _init_database(self, app):
        """Initialize database."""
        from flask_headless_auth import extensions
        
        # ALWAYS use existing db if available
        if 'sqlalchemy' in app.extensions:
            logger.info("Using existing SQLAlchemy from app.extensions")
            self.db = app.extensions['sqlalchemy']
            # Update extensions BEFORE any models are imported
            extensions.set_db(self.db)
        else:
            logger.info("Creating new SQLAlchemy instance")
            self.db = extensions.get_db()
            self.db.init_app(app)
        
        # Always create default models, then override with custom ones
        # Table prefix is configurable per app (e.g. 'mrscribe_', 'brakit_')
        from flask_headless_auth.default_models import create_default_models
        table_prefix = app.config.get('AUTHSVC_TABLE_PREFIX', 'authsvc_')
        (default_user, default_role, default_permission,
         default_blacklisted_token, default_mfa_token,
         default_password_reset_token, default_user_activity_log,
         default_oauth_token, default_audit_log, default_user_session,
         default_activity_log, _) = create_default_models(self.db, table_prefix=table_prefix)
        
        # Use custom models where provided, defaults otherwise
        self.user_model = self.user_model or default_user
        self.role_model = self.role_model or default_role
        self.permission_model = self.permission_model or default_permission
        self.blacklisted_token_model = self.blacklisted_token_model or default_blacklisted_token
        self.mfa_token_model = self.mfa_token_model or default_mfa_token
        self.password_reset_token_model = self.password_reset_token_model or default_password_reset_token
        self.user_activity_log_model = self.user_activity_log_model or default_user_activity_log
        self.oauth_token_model = self.oauth_token_model or default_oauth_token
        
        # Audit models (new)
        self.audit_log_model = self.audit_log_model or default_audit_log
        self.user_session_model = self.user_session_model or default_user_session
        self.activity_log_model = self.activity_log_model or default_activity_log
        
        # Validate user model schema (industry best practice: fail fast at startup)
        if self._custom_models['user']:
            self._validate_user_model_schema()
        
        if self._custom_models['user'] or self._custom_models['role']:
            logger.info(f"Using custom models: {', '.join([k for k,v in self._custom_models.items() if v])}")
        else:
            logger.info("Using all default models")
        
        # Create tables within app context
        with app.app_context():
            # Models are now defined (either default or custom)
            # Just create the tables
            self.db.create_all()
            logger.info(f"Database tables created for models: {self.user_model.__tablename__}")
    
    def _init_jwt(self, app):
        """Initialize JWT."""
        from flask_headless_auth.extensions import get_jwt
        
        self.jwt = get_jwt()
        
        if 'jwt' not in app.extensions:
            self.jwt.init_app(app)
        
        # Setup JWT blacklist checker
        # Need to capture self to access blacklisted_token_model
        blacklisted_token_model = self.blacklisted_token_model
        
        @self.jwt.token_in_blocklist_loader
        def check_if_token_blacklisted(jwt_header, jwt_payload):
            try:
                jti = jwt_payload['jti']
                return blacklisted_token_model.query.filter_by(jti=jti).first() is not None
            except Exception as e:
                # Fail open if blacklist table schema is outdated (better UX than 500 error)
                logger.warning(f"Token blacklist check failed (schema mismatch?): {e}")
                return False  # Assume not blacklisted if we can't check
        
        logger.info("JWT initialized")
    
    def _init_cache_detection(self, app):
        """
        Detect and use existing cache if available (optional).
        
        Cache is optional for flask-headless-auth:
        - If present: Uses it for performance optimization (caching user sessions)
        - If absent: Works perfectly fine without it (direct DB queries)
        
        Supports multiple cache implementations:
        - Redis via Flask-Caching
        - Simple/filesystem cache
        - Any cache in app.extensions
        """
        # Check for cache in extensions (try multiple possible keys)
        if 'cache' in app.extensions:
            cache_obj = app.extensions['cache']
            # Handle dict wrapper (some setups store cache in a dict)
            if isinstance(cache_obj, dict):
                self.cache = next(iter(cache_obj.values()))
                logger.info("✅ Cache detected (key: 'cache', unwrapped from dict) - caching enabled for performance")
            else:
                self.cache = cache_obj
                logger.info("✅ Cache detected (key: 'cache') - caching enabled for performance")
        elif 'flask_caching' in app.extensions:
            cache_obj = app.extensions['flask_caching']
            # Handle dict wrapper (some setups store cache in a dict)
            if isinstance(cache_obj, dict):
                self.cache = next(iter(cache_obj.values()))
                logger.info("✅ Cache detected (key: 'flask_caching', unwrapped from dict) - caching enabled for performance")
            else:
                self.cache = cache_obj
                logger.info("✅ Cache detected (key: 'flask_caching') - caching enabled for performance")
        else:
            self.cache = None
            logger.info("ℹ️  No cache detected - operating without cache (direct DB queries, slightly slower but fully functional)")
    
    def _init_cache_old(self, app):
        """Initialize cache."""
        from flask_headless_auth.extensions import get_cache
        
        self.cache = get_cache()
        
        if 'cache' not in app.extensions:
            self.cache.init_app(app)
        else:
            # Extract cache from extensions dict if needed
            if isinstance(app.extensions['cache'], dict):
                self.cache = next(iter(app.extensions['cache'].values()))
            else:
                self.cache = app.extensions['cache']
    
    def _init_limiter(self, app):
        """Initialize rate limiter."""
        from flask_headless_auth.extensions import get_limiter
        
        if app.config.get('RATELIMIT_ENABLED', True):
            self.limiter = get_limiter()
            
            if 'limiter' not in app.extensions:
                self.limiter.init_app(app)
    
    def _init_cors(self, app):
        """Initialize CORS."""
        from flask_cors import CORS
        
        cors_origins = app.config.get('AUTHSVC_CORS_ORIGINS', ['*'])
        
        if isinstance(cors_origins, str):
            cors_origins = cors_origins.split(',')
        
        CORS(
            app,
            origins=cors_origins,
            supports_credentials=True,
            allow_headers=['Content-Type', 'Authorization', 'X-Requested-With'],
            methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            expose_headers=['Authorization', 'Content-Type'],
        )
        logger.info("CORS initialized")
    
    def _init_security(self, app):
        """Initialize security headers."""
        from flask_talisman import Talisman
        from flask_wtf.csrf import CSRFProtect
        
        force_https = app.config.get('AUTHSVC_FORCE_HTTPS', False)
        
        csp = {
            'default-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", '*.com'],
            'img-src': ['*', 'self', 'blob:', 'data:']
        }
        
        Talisman(app, force_https=force_https, content_security_policy=csp)
        
        # CSRF Protection
        if app.config.get('WTF_CSRF_ENABLED', False):
            CSRFProtect(app)
    
    def _init_email(self, app):
        """Initialize email service if configured."""
        email_service = app.config.get('EMAIL_SERVICE')
        
        if not email_service:
            logger.info("Email service not configured - email verification disabled")
            return
        
        try:
            from flask_headless_auth.email_service import EmailManager
            
            if email_service == 'brevo':
                if not app.config.get('BREVO_API_KEY'):
                    logger.warning("BREVO_API_KEY not configured - email verification disabled")
                    return
            elif email_service == 'gmail':
                if not (app.config.get('MAIL_USERNAME') and app.config.get('MAIL_PASSWORD')):
                    logger.warning("MAIL_USERNAME/MAIL_PASSWORD not configured - email verification disabled")
                    return
            
            email_manager = EmailManager(service_name=email_service, config=app.config)
            app.email_manager = email_manager
            logger.info(f"✅ Email service initialized: {email_service}")
            
        except ImportError as e:
            logger.warning(f"Email service dependencies not installed: {e}")
            logger.info("Install with: pip install flask-headless-auth[email]")
        except Exception as e:
            logger.error(f"Failed to initialize email service: {e}")
    
    def _init_oauth(self, app, **kwargs):
        """Initialize OAuth providers."""
        if not app.config.get('AUTHSVC_ENABLE_OAUTH', True):
            return
        
        from flask_headless_auth.oauth import configure_oauth
        configure_oauth(app, **kwargs)
        
        logger.info("OAuth providers initialized")
    
    def _init_routes(self, app):
        """Register auth routes and RBAC routes."""
        from flask_headless_auth.routes import create_auth_blueprint
        
        # Priority: instance url_prefix > config > default
        url_prefix = self.url_prefix or app.config.get('AUTHSVC_URL_PREFIX', '/api/auth')
        
        # Create unique blueprint name from User model's tablename or use provided
        # This ensures each AuthSvc instance gets a unique blueprint
        if self.blueprint_name:
            blueprint_name = self.blueprint_name
        else:
            user_table = self.user_model.__tablename__
            blueprint_name = f'authsvc_{user_table}'.replace('_users', '')
        
        # Get post-login redirect URL from config or instance variable
        # Priority: app config > instance variable > default
        post_login_redirect_url = (
            app.config.get('POST_LOGIN_REDIRECT_URL') or
            self.post_login_redirect_url or
            'http://localhost:3000'  # Sensible default for development
        )
        
        # Pass email_manager if it exists
        email_manager = getattr(app, 'email_manager', None)
        
        # Create blueprint with model classes, cache, and OAuth config
        auth_bp = create_auth_blueprint(
            user_model=self.user_model,
            blacklisted_token_model=self.blacklisted_token_model,
            mfa_token_model=self.mfa_token_model,
            password_reset_token_model=self.password_reset_token_model,
            user_activity_log_model=self.user_activity_log_model,
            cache=self.cache,  # Pass cache (can be None)
            email_manager=email_manager,
            blueprint_name=blueprint_name,
            post_login_redirect_url=post_login_redirect_url,
            cache_key_prefix=self.cache_key_prefix  # Monorepo support
        )
        app.register_blueprint(auth_bp, url_prefix=url_prefix)
        
        logger.info(f"Auth routes registered at {url_prefix} (blueprint: {blueprint_name})")
        logger.info(f"OAuth post-login redirect URL: {post_login_redirect_url}")
        
        # Register RBAC management routes (if RBAC is enabled)
        if app.config.get('AUTHSVC_ENABLE_RBAC', True):
            self._init_rbac_routes(app, blueprint_name)
        
        # Register audit and session management routes (if enabled)
        if app.config.get('AUTHSVC_ENABLE_AUDIT', True):
            self._init_audit_routes(app, blueprint_name)
        
        # Register admin user-management routes (if enabled)
        if app.config.get('AUTHSVC_ENABLE_ADMIN', True):
            self._init_admin_routes(app, blueprint_name)
    
    def _init_rbac_routes(self, app, base_blueprint_name):
        """Register RBAC management routes."""
        from flask_headless_auth.routes.rbac import create_rbac_blueprint
        
        rbac_url_prefix = app.config.get('AUTHSVC_RBAC_URL_PREFIX', '/api/rbac')
        rbac_blueprint_name = f'{base_blueprint_name}_rbac'
        
        rbac_bp = create_rbac_blueprint(
            role_model=self.role_model,
            permission_model=self.permission_model,
            user_model=self.user_model,
            cache=self.cache,
            blueprint_name=rbac_blueprint_name,
        )
        app.register_blueprint(rbac_bp, url_prefix=rbac_url_prefix)
        
        logger.info(f"RBAC routes registered at {rbac_url_prefix} (blueprint: {rbac_blueprint_name})")
    
    def _init_audit_routes(self, app, base_blueprint_name):
        """Register audit and session management routes."""
        from flask_headless_auth.managers.audit_manager import AuditManager
        from flask_headless_auth.routes.audit import create_audit_blueprint
        
        # Create audit manager
        self.audit_manager = AuditManager(
            audit_log_model=self.audit_log_model,
            user_session_model=self.user_session_model,
            activity_log_model=self.activity_log_model
        )
        
        audit_url_prefix = app.config.get('AUTHSVC_AUDIT_URL_PREFIX', '/api/audit')
        audit_blueprint_name = f'{base_blueprint_name}_audit'
        
        audit_bp = create_audit_blueprint(
            audit_manager=self.audit_manager,
            blueprint_name=audit_blueprint_name
        )
        app.register_blueprint(audit_bp, url_prefix=audit_url_prefix)
        
        logger.info(f"Audit routes registered at {audit_url_prefix} (blueprint: {audit_blueprint_name})")
    
    def _init_admin_routes(self, app, base_blueprint_name):
        """Register admin user-management routes (Clerk / Supabase pattern)."""
        from flask_headless_auth.routes.admin import create_admin_blueprint
        
        # Ensure audit_manager exists (admin routes depend on it for sessions/logging)
        if not hasattr(self, 'audit_manager'):
            from flask_headless_auth.managers.audit_manager import AuditManager
            self.audit_manager = AuditManager(
                audit_log_model=self.audit_log_model,
                user_session_model=self.user_session_model,
                activity_log_model=self.activity_log_model
            )
        
        admin_url_prefix = app.config.get('AUTHSVC_ADMIN_URL_PREFIX', '/api/admin')
        admin_blueprint_name = f'{base_blueprint_name}_admin'
        
        admin_bp = create_admin_blueprint(
            user_model=self.user_model,
            audit_manager=self.audit_manager,
            blueprint_name=admin_blueprint_name,
        )
        app.register_blueprint(admin_bp, url_prefix=admin_url_prefix)
        
        logger.info(f"Admin routes registered at {admin_url_prefix} (blueprint: {admin_blueprint_name})")
    
    def _validate_user_model_schema(self):
        """
        Validate that custom User model has all required fields.
        
        This is an industry best practice: fail fast at startup with clear error messages
        rather than cryptic runtime KeyErrors in production.
        
        Raises:
            ValueError: If required fields are missing with helpful error message
        """
        required_fields = {
            # Core auth fields (CRITICAL)
            'id': 'Integer primary key',
            'email': 'String(255), unique, indexed',
            'password_hash': 'String(1024)',
            
            # Auth flags (CRITICAL - used in login flow)
            'is_verified': 'Boolean, default=False',
            'is_active': 'Boolean, default=True',
            'mfa_enabled': 'Boolean, default=False',  # Used in routes/auth.py:88
            
            # Provider field (CRITICAL - used for OAuth)
            'provider': 'String(50), default="local"',
        }
        
        missing_fields = []
        for field_name, field_desc in required_fields.items():
            if not hasattr(self.user_model, field_name):
                missing_fields.append(f"  - {field_name}: {field_desc}")
        
        if missing_fields:
            table_name = getattr(self.user_model, '__tablename__', 'unknown')
            error_msg = (
                f"\n\n{'='*80}\n"
                f"❌ USER MODEL SCHEMA VALIDATION FAILED\n"
                f"{'='*80}\n\n"
                f"Your custom User model '{self.user_model.__name__}' (table: '{table_name}')\n"
                f"is missing required fields:\n\n"
                f"{chr(10).join(missing_fields)}\n\n"
                f"These fields are required by flask-headless-auth and MUST be added to your model.\n\n"
                f"Example fix:\n\n"
                f"class {self.user_model.__name__}(db.Model, UserMixin):\n"
                f"    __tablename__ = '{table_name}'\n\n"
                f"    # Core auth fields (REQUIRED)\n"
                f"    id = db.Column(db.Integer, primary_key=True)\n"
                f"    email = db.Column(db.String(255), unique=True, nullable=False, index=True)\n"
                f"    password_hash = db.Column(db.String(1024))\n\n"
                f"    # Auth flags (REQUIRED)\n"
                f"    is_verified = db.Column(db.Boolean, nullable=False, default=False)\n"
                f"    is_active = db.Column(db.Boolean, nullable=False, default=True)\n"
                f"    mfa_enabled = db.Column(db.Boolean, nullable=False, default=False)\n\n"
                f"    # Provider (REQUIRED for OAuth)\n"
                f"    provider = db.Column(db.String(50), nullable=False, default='local')\n\n"
                f"    # ... your custom fields ...\n\n"
                f"After adding these fields, run database migration:\n"
                f"  ALTER TABLE {table_name} ADD COLUMN <field_name> <field_type>;\n\n"
                f"Documentation: https://github.com/Dhruvagnihotri/flask-headless-auth#schema\n"
                f"{'='*80}\n"
            )
            raise ValueError(error_msg)

    # ==================================================================
    # AUTH LIFECYCLE HOOKS (Supabase Auth Hooks parity)
    # ==================================================================

    def hook(self, hook_name):
        """
        Decorator to register an auth lifecycle hook.

        Available hooks:
            before_signup, after_signup, before_login, after_login,
            before_logout, after_logout, custom_access_token,
            before_token_refresh, after_token_refresh,
            before_password_change, after_password_change,
            before_mfa_verify, after_mfa_verify,
            on_oauth_login, before_role_assign, after_role_assign

        Usage::

            auth = AuthSvc()

            @auth.hook('before_signup')
            def validate_email_domain(user_data):
                if not user_data['email'].endswith('@company.com'):
                    raise ValueError('Only company emails allowed')

            @auth.hook('custom_access_token')
            def add_org_claims(user, claims):
                claims['tenant_id'] = lookup_tenant(user['id'])
                return claims

        Args:
            hook_name: One of the supported hook names

        Returns:
            Decorator function
        """
        def decorator(fn):
            self.hooks.register(hook_name, fn)
            return fn
        return decorator

    def on(self, hook_name, fn):
        """
        Programmatic hook registration (non-decorator style).

        Usage::
            auth.on('after_login', my_callback)
        """
        self.hooks.register(hook_name, fn)
        return self

