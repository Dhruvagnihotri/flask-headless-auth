"""
flask_headless_auth.managers.audit_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Transparent audit logging and session tracking engine.

Design: Like Supabase's auth.audit_log_entries and auth.sessions --
ALL auth events are logged AUTOMATICALLY. The backend developer
configures nothing. The library calls this internally at every
auth touchpoint (login, signup, logout, token refresh, etc.).

The developer only needs to call audit_manager directly for
APPLICATION-level events (e.g., patient.view, chart.edit) that
live outside the auth library.
"""

import uuid
import hashlib
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import request, current_app
from flask_jwt_extended import get_jwt

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Supabase-equivalent action constants
# (maps to auth.audit_log_entries.action in Supabase)
# ---------------------------------------------------------------------------

class AuditActions:
    """
    Standard audit action types.
    Matches Supabase's auth audit log action types.
    """
    # Auth lifecycle
    USER_SIGNUP = 'user.signup'
    USER_LOGIN = 'user.login'
    USER_LOGOUT = 'user.logout'
    USER_LOGIN_FAILED = 'user.login_failed'

    # Token operations
    TOKEN_REFRESH = 'token.refresh'
    TOKEN_REVOKED = 'token.revoked'

    # Session management
    SESSION_CREATED = 'session.created'
    SESSION_REVOKED = 'session.revoked'
    SESSION_REVOKED_ALL = 'session.revoked_all'
    SESSION_EXPIRED = 'session.expired'
    SESSION_ADMIN_REVOKE = 'session.admin_revoke_all'

    # Account changes
    PASSWORD_CHANGE = 'user.password_change'
    PASSWORD_RESET_REQUEST = 'user.password_reset_request'
    EMAIL_VERIFICATION = 'user.email_verification'
    PROFILE_UPDATE = 'user.profile_update'

    # MFA
    MFA_ENABLED = 'user.mfa_enabled'
    MFA_VERIFIED = 'user.mfa_verified'
    MFA_FAILED = 'user.mfa_failed'

    # OAuth
    OAUTH_LOGIN = 'user.oauth_login'
    OAUTH_SIGNUP = 'user.oauth_signup'

    # Admin user management
    USER_BANNED = 'user.banned'
    USER_UNBANNED = 'user.unbanned'
    USER_SUSPENDED = 'user.suspended'

    # RBAC admin events
    ROLE_ASSIGNED = 'rbac.role_assigned'
    ROLE_REVOKED = 'rbac.role_revoked'
    ROLE_CREATED = 'rbac.role_created'
    ROLE_DELETED = 'rbac.role_deleted'
    PERMISSION_CHANGED = 'rbac.permission_changed'


# ---------------------------------------------------------------------------
# Device fingerprinting helper
# ---------------------------------------------------------------------------

def _parse_device_name(user_agent):
    """Parse user agent into human-readable device name."""
    if not user_agent:
        return 'Unknown Device'

    ua = user_agent.lower()

    # Browser
    browser = 'Unknown Browser'
    if 'edg' in ua:
        browser = 'Edge'
    elif 'chrome' in ua:
        browser = 'Chrome'
    elif 'safari' in ua and 'chrome' not in ua:
        browser = 'Safari'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'postman' in ua:
        browser = 'Postman'

    # OS
    os_name = 'Unknown OS'
    if 'iphone' in ua or 'ipad' in ua:
        os_name = 'iOS'
    elif 'android' in ua:
        os_name = 'Android'
    elif 'windows' in ua:
        os_name = 'Windows'
    elif 'mac' in ua or 'darwin' in ua:
        os_name = 'macOS'
    elif 'linux' in ua:
        os_name = 'Linux'

    return f'{browser} on {os_name}'


def _device_fingerprint(user_agent, ip_address):
    """Generate a stable fingerprint from device signals."""
    data = f'{user_agent or ""}:{ip_address or ""}'
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def _request_context():
    """Extract IP + user-agent from the current Flask request (safe)."""
    try:
        ip = request.remote_addr
        ua = request.user_agent.string if request.user_agent else None
    except RuntimeError:
        ip, ua = None, None
    return ip, ua


# ---------------------------------------------------------------------------
# AuditManager
# ---------------------------------------------------------------------------

class AuditManager:
    """
    Centralized audit and session engine.

    Instantiated once in AuthSvc._init_audit_routes() and stored as
    ``current_app.extensions['authsvc'].audit_manager``.

    All public methods are **fire-and-forget safe** -- they never raise,
    never break the calling auth flow, and log errors instead.
    """

    def __init__(self, audit_log_model, user_session_model, activity_log_model,
                 db_session=None):
        self.AuditLog = audit_log_model
        self.UserSession = user_session_model
        self.ActivityLog = activity_log_model
        self._db_session = db_session

    @property
    def db(self):
        if self._db_session:
            return self._db_session
        from flask_headless_auth import extensions
        return extensions.db or extensions.get_db()

    # ==================================================================
    # AUDIT LOGGING  (Supabase auth.audit_log_entries parity)
    # ==================================================================

    def log_event(self, action, user_id=None, success=True,
                  error_message=None, metadata=None, session_id=None,
                  target_user_id=None, tenant_id=None):
        """
        Write one row to the audit log.  Called internally by the auth
        routes -- the backend developer never needs to call this for
        standard auth events.

        Safe: swallows all exceptions so it never breaks the auth flow.

        Args:
            tenant_id: Optional tenant/org ID for multi-tenancy.
                       Auto-resolved from JWT claims if not provided.
        """
        try:
            ip, ua = _request_context()

            # Resolve tenant_id: explicit arg > JWT claim > None
            if tenant_id is None:
                try:
                    claims = get_jwt()
                    tenant_id = claims.get('tenant_id')
                except Exception:
                    pass

            entry = self.AuditLog(
                action=action,
                actor_user_id=user_id,
                target_user_id=target_user_id,
                session_id=session_id,
                ip_address=ip,
                user_agent=ua,
                success=success,
                error_message=error_message,
                event_metadata=metadata or {},
                tenant_id=tenant_id,
            )
            self.db.session.add(entry)
            self.db.session.commit()
        except Exception as exc:
            logger.warning(f'Audit log write failed (non-fatal): {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_audit_logs(self, user_id=None, action=None, tenant_id=None,
                       success=None, start_date=None, end_date=None,
                       limit=100, offset=0):
        """Return audit log rows with optional filters."""
        q = self.AuditLog.query

        if user_id is not None:
            q = q.filter_by(actor_user_id=user_id)
        if action:
            q = q.filter_by(action=action)
        if tenant_id is not None:
            q = q.filter_by(tenant_id=tenant_id)
        if success is not None:
            q = q.filter_by(success=success)
        if start_date:
            q = q.filter(self.AuditLog.timestamp >= start_date)
        if end_date:
            q = q.filter(self.AuditLog.timestamp <= end_date)

        return (q.order_by(self.AuditLog.timestamp.desc())
                 .limit(limit).offset(offset).all())

    def get_failed_login_count(self, user_id=None, ip_address=None,
                               window_minutes=30):
        """Count recent failed logins (for brute-force detection)."""
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        q = self.AuditLog.query.filter(
            self.AuditLog.action == AuditActions.USER_LOGIN_FAILED,
            self.AuditLog.timestamp >= cutoff,
        )
        if user_id:
            q = q.filter_by(actor_user_id=user_id)
        if ip_address:
            q = q.filter_by(ip_address=ip_address)
        return q.count()

    # ==================================================================
    # SESSION MANAGEMENT  (Supabase auth.sessions parity)
    # ==================================================================

    def create_session(self, user_id, jti, tenant_id=None):
        """
        Create a new session row.  Called automatically inside
        TokenManager.generate_token_authsvc().

        Args:
            tenant_id: Optional tenant/org ID for multi-tenancy.

        Returns the session_id (UUID string) to embed in the JWT.
        """
        try:
            ip, ua = _request_context()
            sid = str(uuid.uuid4())

            # Optional: session timeout from config
            expires_at = None
            try:
                timeout = current_app.config.get('AUTHSVC_SESSION_TIMEOUT_MINUTES')
                if timeout:
                    expires_at = datetime.utcnow() + timedelta(minutes=int(timeout))
            except Exception:
                pass

            session = self.UserSession(
                session_id=sid,
                user_id=user_id,
                jti=jti,
                ip_address=ip,
                user_agent=ua,
                device_name=_parse_device_name(ua),
                device_fingerprint=_device_fingerprint(ua, ip),
                expires_at=expires_at,
                tenant_id=tenant_id,
            )
            self.db.session.add(session)
            self.db.session.commit()

            logger.debug(f'Session {sid} created for user {user_id}')
            return sid
        except Exception as exc:
            logger.warning(f'Session creation failed (non-fatal): {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass
            return str(uuid.uuid4())  # return a UUID anyway so the JWT is valid

    def touch_session(self, jti):
        """
        Update last_activity on token refresh.

        If ``AUTHSVC_SESSION_INACTIVITY_TIMEOUT`` is configured and the
        session has been idle longer than that, the session is **revoked**
        instead of touched.

        Returns:
            True  -- session is alive, refresh should proceed.
            False -- session was idle too long (or not found), refresh
                     should be rejected.
        """
        try:
            session = self.UserSession.query.filter_by(jti=jti, revoked=False).first()
            if not session:
                return False

            now = datetime.utcnow()

            # --- Inactivity timeout enforcement (Supabase Pro parity) ---
            try:
                inactivity_minutes = current_app.config.get(
                    'AUTHSVC_SESSION_INACTIVITY_TIMEOUT')
                if inactivity_minutes:
                    cutoff = now - timedelta(minutes=int(inactivity_minutes))
                    if session.last_activity < cutoff:
                        # Session has been idle too long -- revoke it
                        session.is_active = False
                        session.revoked = True
                        session.revoked_at = now
                        session.revoke_reason = 'inactivity_timeout'
                        self.db.session.commit()

                        self.log_event(
                            action='session.expired',
                            user_id=session.user_id,
                            session_id=session.session_id,
                            metadata={
                                'reason': 'inactivity_timeout',
                                'idle_minutes': int(
                                    (now - session.last_activity).total_seconds() / 60),
                            },
                        )
                        logger.debug(
                            f'Session {session.session_id} revoked: inactive for >{inactivity_minutes} min')
                        return False
            except Exception:
                pass  # If config parsing fails, skip the check

            # Session is alive -- update last_activity
            session.last_activity = now
            self.db.session.commit()
            return True
        except Exception as exc:
            logger.warning(f'Session touch failed (non-fatal): {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass
            return True  # Fail-open: don't break refresh on unexpected errors

    def revoke_session_by_jti(self, jti, reason='user_logout'):
        """Revoke the session tied to a JWT.  Called on logout."""
        try:
            session = self.UserSession.query.filter_by(jti=jti, revoked=False).first()
            if session:
                session.is_active = False
                session.revoked = True
                session.revoked_at = datetime.utcnow()
                session.revoke_reason = reason
                self.db.session.commit()
        except Exception as exc:
            logger.warning(f'Session revoke failed (non-fatal): {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass

    def get_user_sessions(self, user_id, active_only=True):
        """Return sessions for a user."""
        q = self.UserSession.query.filter_by(user_id=user_id)
        if active_only:
            q = q.filter_by(is_active=True, revoked=False)
        return q.order_by(self.UserSession.last_activity.desc()).all()

    def revoke_all_user_sessions(self, user_id, except_jti=None):
        """Logout from all devices.  Returns count revoked."""
        try:
            q = self.UserSession.query.filter_by(
                user_id=user_id, is_active=True, revoked=False
            )
            if except_jti:
                q = q.filter(self.UserSession.jti != except_jti)

            sessions = q.all()
            now = datetime.utcnow()
            for s in sessions:
                s.is_active = False
                s.revoked = True
                s.revoked_at = now
                s.revoke_reason = 'user_logout_all'
            self.db.session.commit()
            return len(sessions)
        except Exception as exc:
            logger.warning(f'Bulk session revoke failed: {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass
            return 0

    def enforce_single_session(self, user_id, current_jti):
        """
        If AUTHSVC_SINGLE_SESSION_PER_USER is True, revoke all
        other sessions.  Called automatically after token generation.
        """
        try:
            if current_app.config.get('AUTHSVC_SINGLE_SESSION_PER_USER', False):
                return self.revoke_all_user_sessions(user_id, except_jti=current_jti)
        except Exception:
            pass
        return 0

    def cleanup_expired_sessions(self):
        """
        Periodic task: mark expired and inactive sessions as revoked.

        Handles both:
        1. Sessions past their ``expires_at`` (hard timeout)
        2. Sessions idle longer than ``AUTHSVC_SESSION_INACTIVITY_TIMEOUT``

        Call this from a scheduler (e.g., APScheduler, Celery beat) or
        a management command.
        """
        try:
            now = datetime.utcnow()
            revoked_count = 0

            # 1. Hard expiry (AUTHSVC_SESSION_TIMEOUT_MINUTES)
            expired = self.UserSession.query.filter(
                self.UserSession.is_active == True,
                self.UserSession.expires_at != None,
                self.UserSession.expires_at < now,
            ).all()
            for s in expired:
                s.is_active = False
                s.revoked = True
                s.revoked_at = now
                s.revoke_reason = 'session_expired'
            revoked_count += len(expired)

            # 2. Inactivity timeout (AUTHSVC_SESSION_INACTIVITY_TIMEOUT)
            try:
                inactivity_minutes = current_app.config.get(
                    'AUTHSVC_SESSION_INACTIVITY_TIMEOUT')
                if inactivity_minutes:
                    cutoff = now - timedelta(minutes=int(inactivity_minutes))
                    inactive = self.UserSession.query.filter(
                        self.UserSession.is_active == True,
                        self.UserSession.revoked == False,
                        self.UserSession.last_activity < cutoff,
                    ).all()
                    for s in inactive:
                        s.is_active = False
                        s.revoked = True
                        s.revoked_at = now
                        s.revoke_reason = 'inactivity_timeout'
                    revoked_count += len(inactive)
            except Exception:
                pass

            self.db.session.commit()
            return revoked_count
        except Exception as exc:
            logger.warning(f'Session cleanup failed: {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass
            return 0

    # ==================================================================
    # ACTIVITY LOGGING  (generic app-level events)
    # ==================================================================

    def log_activity(self, user_id, action, resource_type=None,
                     resource_id=None, metadata=None, tenant_id=None):
        """
        Log an application-level event.

        This IS the one method the backend developer calls explicitly
        for domain-specific events (e.g. invoice.created, order.shipped)
        that live outside the auth library.

        Args:
            user_id:       The user performing the action.
            action:        A string like 'order.created', 'report.exported'.
            resource_type: Optional resource category (e.g. 'order').
            resource_id:   Optional resource ID.
            metadata:      Optional dict for any extra context the app
                           needs to store (compliance flags, tags, etc.).
            tenant_id:     Optional tenant/org ID.  Auto-resolved from
                           JWT claim if not provided.
        """
        try:
            ip, ua = _request_context()
            session_id = None

            # Resolve tenant_id: explicit arg > JWT claim > None
            if tenant_id is None:
                try:
                    claims = get_jwt()
                    tenant_id = claims.get('tenant_id')
                    session_id = claims.get('session_id')
                except Exception:
                    pass
            else:
                try:
                    claims = get_jwt()
                    session_id = claims.get('session_id')
                except Exception:
                    pass

            entry = self.ActivityLog(
                user_id=user_id,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                session_id=session_id,
                ip_address=ip,
                user_agent=ua,
                tenant_id=tenant_id,
                event_metadata=metadata or {},
            )
            self.db.session.add(entry)
            self.db.session.commit()
        except Exception as exc:
            logger.warning(f'Activity log write failed (non-fatal): {exc}')
            try:
                self.db.session.rollback()
            except Exception:
                pass

    def get_user_activity(self, user_id, limit=100, offset=0):
        q = self.ActivityLog.query.filter_by(user_id=user_id)
        return (q.order_by(self.ActivityLog.timestamp.desc())
                 .limit(limit).offset(offset).all())

    def get_resource_access_history(self, resource_type, resource_id,
                                     limit=100):
        q = self.ActivityLog.query.filter_by(
            resource_type=resource_type, resource_id=resource_id
        )
        return (q.order_by(self.ActivityLog.timestamp.desc())
                 .limit(limit).all())


# ---------------------------------------------------------------------------
# Convenience decorator for app-level activity logging
# ---------------------------------------------------------------------------

def audit_action(action_type, resource_type=None, metadata=None):
    """
    Decorator for application routes to automatically log activity.

    The library records *who* accessed *what* and stores any extra context
    you provide in ``metadata`` (a dict or a callable that receives
    ``**kwargs`` from the route and returns a dict).

    Usage::

        @app.route('/api/orders/<int:order_id>')
        @jwt_required()
        @permission_required('orders.view')
        @audit_action('order.viewed', resource_type='order')
        def get_order(order_id):
            return jsonify(order)

        # With static metadata:
        @audit_action('record.viewed', resource_type='record',
                      metadata={'sensitive': True})

        # With dynamic metadata (callable receives route kwargs):
        @audit_action('record.viewed', resource_type='record',
                      metadata=lambda **kw: {'record_id': kw.get('record_id')})
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            result = f(*args, **kwargs)

            # Log after successful execution
            try:
                claims = get_jwt()
                user_id = claims.get('id')
                if user_id:
                    authsvc = current_app.extensions.get('authsvc')
                    if authsvc and hasattr(authsvc, 'audit_manager'):
                        resource_id = kwargs.get(
                            f'{resource_type}_id') if resource_type else None

                        # Resolve metadata: static dict or callable
                        extra = {}
                        if callable(metadata):
                            try:
                                extra = metadata(**kwargs) or {}
                            except Exception:
                                extra = {}
                        elif isinstance(metadata, dict):
                            extra = metadata

                        authsvc.audit_manager.log_activity(
                            user_id=user_id,
                            action=action_type,
                            resource_type=resource_type,
                            resource_id=resource_id,
                            metadata=extra,
                        )
            except Exception as exc:
                logger.warning(f'audit_action decorator failed (non-fatal): {exc}')

            return result
        return wrapper
    return decorator
