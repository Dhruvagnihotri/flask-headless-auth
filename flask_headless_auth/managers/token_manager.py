"""
flask_headless_auth.managers.token_manager
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Token generation, delivery, refresh, and blacklisting.

IMPORTANT – This is the **choke point** for every authenticated action:
login, signup, OAuth callback, MFA verify, and token refresh all flow
through here.  Audit logging and session tracking are wired in
transparently so the backend developer gets Supabase-level audit
coverage with zero configuration.
"""

from flask_jwt_extended import (
    create_access_token, create_refresh_token, get_jwt, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, verify_jwt_in_request
)
from flask import jsonify, make_response, request, current_app
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from flask_headless_auth.interfaces import UserDataAccess

logger = logging.getLogger(__name__)


def _get_audit_manager():
    """Safely get the AuditManager (returns None if audit is disabled)."""
    try:
        authsvc = current_app.extensions.get('authsvc')
        if authsvc and hasattr(authsvc, 'audit_manager'):
            return authsvc.audit_manager
    except Exception:
        pass
    return None


def _get_hooks_manager():
    """Safely get the HooksManager (returns None if not initialised)."""
    try:
        authsvc = current_app.extensions.get('authsvc')
        if authsvc and hasattr(authsvc, 'hooks'):
            return authsvc.hooks
    except Exception:
        pass
    return None


class TokenManager:
    def __init__(self, user_data_access: UserDataAccess):
        self.user_data_access = user_data_access

    # ------------------------------------------------------------------
    # Core token generation (session + audit baked in)
    # ------------------------------------------------------------------

    def generate_token_authsvc(self, user, additional_claims=None,
                               audit_action=None):
        """
        Generate access + refresh tokens for a user.

        Automatically:
        1. Creates a session row in authsvc_user_sessions
        2. Logs the auth event in authsvc_audit_log_entries
        3. Embeds session_id in JWT claims (for session tracking)
        4. Enforces single-session policy if configured

        Args:
            user: User dict with id, email, role_id, etc.
            additional_claims: Extra JWT claims dict
            audit_action: Override audit action string (auto-detected if None)
        """
        logger.debug(f"Generating token for user ID: {user.get('id')}")
        identity = user['email']

        role_id = user.get('role_id')
        role_name = None
        permissions = []

        # Resolve role name and permissions from database if RBAC is enabled
        if role_id and current_app.config.get('AUTHSVC_ENABLE_RBAC', True):
            try:
                authsvc = current_app.extensions.get('authsvc')
                if authsvc and authsvc.role_model:
                    role = authsvc.role_model.query.get(role_id)
                    if role:
                        role_name = role.name
                        permissions = [p.name for p in role.permissions]
            except Exception as e:
                logger.warning(f"Could not resolve role details for JWT: {e}")

        # ------- Session creation (automatic) -------
        session_id = None
        audit_mgr = _get_audit_manager()
        if audit_mgr:
            # Create a placeholder JTI so we can create the session first
            # (flask-jwt-extended generates the real JTI, but we need the
            #  session_id BEFORE we create the token so it's in the claims)
            import uuid
            placeholder_jti = str(uuid.uuid4())
            session_id = audit_mgr.create_session(
                user_id=user['id'],
                jti=placeholder_jti,
                tenant_id=user.get('tenant_id'),
            )

        # ------- Build JWT claims -------
        claims = {
            'id': user['id'],
            'role': role_id,
            'role_name': role_name,
            'permissions': permissions,
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'email': user['email'],
            'session_id': session_id,  # Track which session this token belongs to
        }
        if additional_claims:
            claims.update(additional_claims)

        # ------- custom_access_token hook (Supabase parity) -------
        # Allows the app to inject custom claims (tenant_id, org, etc.)
        hooks = _get_hooks_manager()
        if hooks and hooks.has_hooks('custom_access_token'):
            try:
                modified = hooks.fire('custom_access_token', user, claims,
                                      default_return=claims)
                if isinstance(modified, dict):
                    claims = modified
            except Exception as exc:
                logger.warning(f'custom_access_token hook failed: {exc}')

        access_token = create_access_token(identity=identity,
                                           additional_claims=claims)
        refresh_token = create_refresh_token(identity=identity,
                                             additional_claims=claims)

        # ------- Audit log (automatic) -------
        if audit_mgr:
            action = audit_action or 'user.login'
            audit_mgr.log_event(
                action=action,
                user_id=user['id'],
                session_id=session_id,
                metadata={
                    'provider': user.get('provider', 'local'),
                    'role': role_name,
                },
            )
            # Enforce single-session policy if configured
            audit_mgr.enforce_single_session(user['id'], placeholder_jti)

        return {'access_token': access_token, 'refresh_token': refresh_token}

    # ------------------------------------------------------------------
    # Token delivery modes
    # ------------------------------------------------------------------

    @staticmethod
    def is_browser_request():
        """Check if request is from a browser (vs API client like Postman)."""
        user_agent = request.headers.get('User-Agent', '').lower()
        browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'trident', 'msie']
        return any(browser in user_agent for browser in browsers)

    def generate_token_and_set_cookies(self, user, audit_action=None):
        """
        Configurable token delivery with secure defaults.

        Three modes (configured via AUTHSVC_TOKEN_DELIVERY):
        1. 'cookies_only' (DEFAULT - Most Secure)
        2. 'body_only' (For APIs)
        3. 'dual' (Flexible - Backwards Compatible)
        """
        tokens = self.generate_token_authsvc(user, audit_action=audit_action)
        is_browser = self.is_browser_request()

        delivery_mode = current_app.config.get('AUTHSVC_TOKEN_DELIVERY', 'cookies_only')

        if delivery_mode == 'cookies_only':
            response_data = {
                'msg': 'Login successful',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'role': user.get('role_id', 2)
                }
            }
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])
            else:
                response_data['access_token'] = tokens['access_token']
                response_data['refresh_token'] = tokens['refresh_token']
                response = make_response(jsonify(response_data))

        elif delivery_mode == 'body_only':
            response_data = {
                'msg': 'Login successful',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            response = make_response(jsonify(response_data))

        elif delivery_mode == 'dual':
            response_data = {
                'msg': 'Login successful',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])

        else:
            logger.error(f"Invalid AUTHSVC_TOKEN_DELIVERY mode: {delivery_mode}. Using 'cookies_only'")
            response_data = {
                'msg': 'Login successful',
                'user': {'id': user['id'], 'email': user['email']}
            }
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])

        return response

    def refresh_token_and_set_cookies(self, user):
        """
        Refresh tokens. Automatically:
        - Checks inactivity timeout (revokes session if idle too long)
        - Updates session last_activity
        - Logs token.refresh audit event
        """
        # Touch the current session -- returns False if the session was
        # revoked due to inactivity timeout
        audit_mgr = _get_audit_manager()
        if audit_mgr:
            try:
                claims = get_jwt()
                old_jti = claims.get('jti')
                if old_jti:
                    session_alive = audit_mgr.touch_session(old_jti)
                    if not session_alive:
                        # Session expired due to inactivity -- force re-login
                        response = make_response(jsonify({
                            'error': 'Session expired due to inactivity. Please log in again.',
                            'error_code': 'SESSION_INACTIVE',
                        }), 401)
                        unset_jwt_cookies(response)
                        return response
            except Exception:
                pass

        tokens = self.generate_token_authsvc(user, audit_action='token.refresh')
        is_browser = self.is_browser_request()

        delivery_mode = current_app.config.get('AUTHSVC_TOKEN_DELIVERY', 'cookies_only')

        if delivery_mode == 'cookies_only':
            response_data = {'msg': 'Token refreshed successfully'}
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])
            else:
                response_data['access_token'] = tokens['access_token']
                response_data['refresh_token'] = tokens['refresh_token']
                response = make_response(jsonify(response_data))

        elif delivery_mode == 'body_only':
            response_data = {
                'msg': 'Token refreshed successfully',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            response = make_response(jsonify(response_data))

        elif delivery_mode == 'dual':
            response_data = {
                'msg': 'Token refreshed successfully',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])

        else:
            response_data = {'msg': 'Token refreshed successfully'}
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])

        return response

    def generate_token_and_redirect(self, user, redirect_uri):
        """OAuth callback token delivery."""
        try:
            tokens = self.generate_token_authsvc(
                user, audit_action='user.oauth_login')
            is_browser = self.is_browser_request()
            delivery_mode = current_app.config.get('AUTHSVC_TOKEN_DELIVERY', 'cookies_only')

            if delivery_mode == 'cookies_only':
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                if is_browser:
                    set_access_cookies(response, tokens['access_token'])
                    set_refresh_cookies(response, tokens['refresh_token'])
                else:
                    redirect_uri = self._append_tokens_to_url(redirect_uri, tokens)
                    response.headers['Location'] = redirect_uri

            elif delivery_mode == 'body_only':
                redirect_uri = self._append_tokens_to_url(redirect_uri, tokens)
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri

            elif delivery_mode == 'dual':
                redirect_uri = self._append_tokens_to_url(redirect_uri, tokens)
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                if is_browser:
                    set_access_cookies(response, tokens['access_token'])
                    set_refresh_cookies(response, tokens['refresh_token'])

            else:
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                if is_browser:
                    set_access_cookies(response, tokens['access_token'])
                    set_refresh_cookies(response, tokens['refresh_token'])

            return response

        except Exception as e:
            logger.error(f"Error in generate_token_and_redirect: {e}")
            error_response = make_response('', 302)
            error_response.headers['Location'] = f"{redirect_uri}?error=token_generation_failed"
            return error_response

    # ------------------------------------------------------------------
    # Token blacklisting + session revocation
    # ------------------------------------------------------------------

    def blacklist_token_authsvc(self):
        """
        Blacklist the current JWT AND revoke its session.
        Automatically logs the logout event.
        """
        try:
            verify_jwt_in_request()
            claims = get_jwt()
            jti = claims.get('jti')
            user_id = claims.get('id')
            session_id = claims.get('session_id')

            if not jti:
                return jsonify({'error': 'JWT ID not found in token.'}), 400

            if self.user_data_access.is_token_blacklisted(jti):
                return jsonify({'msg': 'Token is already blacklisted.'}), 200

            self.user_data_access.blacklist_token(jti)

            # Revoke the session + audit log
            audit_mgr = _get_audit_manager()
            if audit_mgr:
                audit_mgr.revoke_session_by_jti(jti, reason='user_logout')
                audit_mgr.log_event(
                    action='user.logout',
                    user_id=user_id,
                    session_id=session_id,
                )

            return jsonify({'msg': 'Token successfully blacklisted.'}), 200

        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            return jsonify({'error': 'Error blacklisting token', 'details': str(e)}), 500

    def verify_mfa_authsvc(self, user, token):
        return self.user_data_access.verify_mfa_token(user['id'], token)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _append_tokens_to_url(self, redirect_uri, tokens):
        try:
            parsed_url = urlparse(redirect_uri)
            query_params = parse_qs(parsed_url.query)
            query_params['access_token'] = [tokens['access_token']]
            query_params['refresh_token'] = [tokens['refresh_token']]
            new_query = urlencode(query_params, doseq=True)
            return urlunparse((
                parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                parsed_url.params, new_query, parsed_url.fragment
            ))
        except Exception as e:
            logger.error(f"Error appending tokens to URL: {e}")
            return redirect_uri
