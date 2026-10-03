import base64
import json
import logging
import time
import requests
from urllib.parse import urlsplit
from flask import request, url_for, jsonify, session, current_app
from sqlalchemy.exc import IntegrityError, OperationalError
from flask_headless_auth.oauth.providers import oauth_clients
from flask_headless_auth.interfaces import UserDataAccess
from flask_headless_auth.oauth.stateless_handler import StatelessOAuthStateHandler

logger = logging.getLogger(__name__)


# MySQL error codes that mean "the connection itself died or never opened" -
# confirmed from real PDFCourt production incidents (2003, 2013) plus the
# same family's documented sibling (2006). Deliberately NOT a bare
# OperationalError catch: pymysql also raises this class for access-denied
# (1045), too-many-connections (1040), and lock-wait-timeout (1205) - none
# of those are helped by a retry, and retrying "too many connections" during
# a real connection storm would add load at the worst possible moment.
_TRANSIENT_MYSQL_CONNECTION_ERROR_CODES = {2003, 2006, 2013}


def _is_transient_connection_error(exc: OperationalError) -> bool:
    orig = getattr(exc, 'orig', None)
    code = orig.args[0] if orig is not None and getattr(orig, 'args', None) else None
    return code in _TRANSIENT_MYSQL_CONNECTION_ERROR_CODES


def _call_with_db_retry(fn, user_data_access, *, retries=1, backoff_seconds=0.3):
    """
    Retry fn() on a transient connection-level OperationalError (dropped
    connection / handshake timeout to a remote DB-as-a-service host, not a
    logic error) - see _is_transient_connection_error for exactly which
    error codes qualify.

    Confirmed recurring in production (PDFCourt, 2026-09-25/28/29):
    `pymysql.err.OperationalError` (2003 "handshake operation timed out",
    2013 "Lost connection to MySQL server during query") hit google_callback
    directly, 500ing a real user's login with no recovery. pool_pre_ping
    (already configured app-wide) only tests an EXISTING pooled connection
    before handing it out - it can't help when a connection dies mid-query,
    or when opening a brand-new replacement connection itself times out on
    the handshake. Only an application-level retry closes that gap.

    Takes `user_data_access` rather than its `.db.session` directly, and
    only reaches for `.db.session` inside the except block (never on the
    happy path) - some consuming app's custom UserDataAccess implementation
    might not have a `.db` attribute at all, and eagerly evaluating it on
    every single login (success or not) would turn a login-time
    AttributeError into a hard failure for every OAuth login on that app,
    not just the rare transient-error path this is meant to protect.

    retries=1 (not higher): pdfwiz's gunicorn config pairs a 30s MySQL
    read_timeout with only a 30s default worker timeout (its own Procfile) -
    a second retry on a mid-query read-timeout failure (3 x 30s = 90s)
    would get the worker killed before it could even finish, making the
    extra attempt pure downside. One retry covers the observed failure
    shape (a single dead pooled connection) without that risk.
    """
    last_exc = None
    for attempt in range(retries + 1):
        try:
            return fn()
        except OperationalError as e:
            if not _is_transient_connection_error(e):
                raise
            last_exc = e
            session = getattr(getattr(user_data_access, 'db', None), 'session', None)
            if session is not None:
                try:
                    session.rollback()
                except Exception as rollback_exc:
                    logger.warning(
                        f"[StatelessOAuth] rollback() itself failed while recovering "
                        f"from a transient DB error: {rollback_exc}"
                    )
            if attempt < retries:
                logger.warning(
                    f"[StatelessOAuth] Transient DB connection error on attempt "
                    f"{attempt + 1}/{retries + 1}, retrying: {getattr(e, 'orig', e)}"
                )
                time.sleep(backoff_seconds)
    raise last_exc


def _find_or_create_oauth_user(user_data_access, email, user_data):
    """
    Find a user by email, creating one if none exists - safe against the
    concurrent-request race where two OAuth callbacks for the same email
    (e.g. a double-clicked "Sign in with Google", or a silent re-auth firing
    while a previous one is still in flight) both see find_user_by_email
    return None and both attempt create_user.

    Confirmed happening in production (2026-09-24, PDFCourt): an EXISTING
    user with an active trial got a 500 from a duplicate-key IntegrityError
    on the email unique index during google_callback, immediately followed
    by "This Session's transaction has been rolled back due to a previous
    exception during flush" on a later, unrelated request - this code had
    no rollback() anywhere, so the session stayed poisoned until something
    else's request finally rolled it back.

    Pre-checking with find_user_by_email (still done by the caller, for the
    common non-racing path) can never fully close this gap on its own -
    there's always a window between that read and the insert. The DB's own
    unique constraint is the real source of truth, so on a duplicate-key
    violation here, roll back and re-fetch: the other, winning, concurrent
    request already created the row we wanted, so use it instead of
    crashing. Returns (user, is_new_user).
    """
    try:
        return user_data_access.create_user(user_data), True
    except IntegrityError:
        user_data_access.db.session.rollback()
        existing = user_data_access.find_user_by_email(email)
        if existing is None:
            # We failed to insert because the row exists, but can't find it
            # even right after rolling back - genuinely unexpected, don't
            # paper over it.
            raise
        logger.info(
            f"[StatelessOAuth] Concurrent create_user race for {email} - "
            f"another request created it first, using that row"
        )
        return existing, False


def _resolve_redirect_uri(requested_uri, default_uri):
    """
    CWE-601 (open redirect) guard: `redirect_uri` on /login/google and
    /login/microsoft is caller-supplied — signing it into the OAuth state
    (see StatelessOAuthStateHandler) stops an attacker from *tampering*
    with it in transit, but does nothing to stop them from *choosing* a
    malicious value in the first place (e.g. a phished link with
    `?redirect_uri=https://evil.example/steal`), since the signature is
    only ever checked for integrity, not origin.

    If AUTHSVC_ALLOWED_REDIRECT_ORIGINS is configured, enforce it and fall
    back to default_uri on any mismatch. If it isn't configured, this is
    intentionally warn-only rather than enforced same-origin-by-default:
    several apps already rely on a caller-supplied redirect_uri in
    production without ever having set this, and silently changing that
    behavior here could break a live login flow. The warning makes the
    gap visible so an app owner can opt in deliberately.
    """
    allowed_origins = current_app.config.get('AUTHSVC_ALLOWED_REDIRECT_ORIGINS')
    if not allowed_origins:
        logger.warning(
            "AUTHSVC_ALLOWED_REDIRECT_ORIGINS is not configured — "
            "redirect_uri from the OAuth login request is accepted as-is. "
            "Set it to a list of allowed origins (e.g. ['https://yourapp.com']) "
            "to close this open-redirect surface."
        )
        return requested_uri

    requested_origin = f"{urlsplit(requested_uri).scheme}://{urlsplit(requested_uri).netloc}"
    if requested_origin in allowed_origins:
        return requested_uri

    logger.warning(
        f"Rejected redirect_uri with disallowed origin '{requested_origin}' "
        f"(allowed: {allowed_origins}) — falling back to default redirect"
    )
    return default_uri


def _get_callback_uri(blueprint_name, endpoint_name):
    """
    Generate OAuth callback URI with proper HTTPS scheme detection.
    
    Handles production environments behind proxies (Heroku, AWS, etc.) that terminate SSL.
    Respects X-Forwarded-Proto header to determine if request came via HTTPS.
    """
    # Check if we're behind a HTTPS proxy (Heroku, CloudFlare, AWS ELB, etc.)
    forwarded_proto = request.headers.get('X-Forwarded-Proto', 'http')
    is_secure = forwarded_proto == 'https' or request.is_secure
    
    # Generate URL with appropriate scheme
    callback_uri = url_for(
        f'{blueprint_name}.{endpoint_name}',
        _external=True,
        _scheme='https' if is_secure else 'http'
    )
    
    return callback_uri

class OAuthManager:
    def __init__(self, user_data_access: UserDataAccess, 
                 blueprint_name='authsvc', 
                 post_login_redirect_url='http://localhost:3000'):
        """
        Initialize OAuth manager with dynamic configuration.
        
        Args:
            user_data_access: User data access layer
            blueprint_name: Dynamic blueprint name for url_for() (e.g., 'authsvc_whogoesnext')
            post_login_redirect_url: Default frontend URL for OAuth redirects
        """
        self.user_data_access = user_data_access
        self.blueprint_name = blueprint_name
        self.post_login_redirect_url = post_login_redirect_url
        self.stateless_handler = StatelessOAuthStateHandler()
        logger.info(f"OAuthManager initialized with blueprint: {blueprint_name}, redirect: {post_login_redirect_url}")
        logger.info(f"OAuthManager using self-contained signed state (no Redis/sessions needed)")

    _microsoft_jwks_client = None

    def _verify_microsoft_id_token(self, id_token):
        """
        Verify a Microsoft-issued ID token's signature against Microsoft's
        published JWKS, and check standard OIDC claims. Raises ValueError
        on any failure (mirrors this file's existing error-handling style).

        Issuer is validated by prefix/suffix rather than exact match: the
        token exchange above uses the multi-tenant 'common' endpoint, so
        the real `iss` claim contains whichever tenant actually authenticated
        (https://login.microsoftonline.com/{tenant-guid}/v2.0), not the
        literal string 'common'. This is the standard approach for
        multi-tenant app registrations — audience is what actually pins
        the token to this app.
        """
        import jwt as pyjwt

        if not id_token:
            raise ValueError("No id_token in Microsoft token response")

        if OAuthManager._microsoft_jwks_client is None:
            OAuthManager._microsoft_jwks_client = pyjwt.PyJWKClient(
                'https://login.microsoftonline.com/common/discovery/v2.0/keys'
            )

        signing_key = OAuthManager._microsoft_jwks_client.get_signing_key_from_jwt(id_token)
        claims = pyjwt.decode(
            id_token,
            signing_key.key,
            algorithms=['RS256'],
            audience=oauth_clients.microsoft.client_id,
        )

        issuer = claims.get('iss', '')
        if not (issuer.startswith('https://login.microsoftonline.com/') and issuer.endswith('/v2.0')):
            raise ValueError(f"Unexpected Microsoft id_token issuer: {issuer!r}")

        return claims

    def google_login(self):
        try:
            # Use dynamic blueprint name for backend callback URL with HTTPS detection
            backend_callback_uri = _get_callback_uri(self.blueprint_name, 'google_callback_authsvc')
            
            # Get frontend redirect URI
            frontend_redirect_uri = _resolve_redirect_uri(
                request.args.get('redirect_uri', self.post_login_redirect_url),
                self.post_login_redirect_url
            )
            
            # Collect custom data from query params
            # Skip 'redirect_uri' as it's handled separately
            # This allows apps to pass any custom data through OAuth flow
            custom_data = {
                key: value 
                for key, value in request.args.items() 
                if key != 'redirect_uri'
            }
            
            # Generate custom state and store redirect_uri + custom_data
            state = self.stateless_handler.save_state(
                frontend_redirect_uri, 
                custom_data=custom_data if custom_data else None
            )
            
            logger.info(f"[StatelessOAuth] Google login initiated:")
            logger.info(f"  Backend callback: {backend_callback_uri}")
            logger.info(f"  Frontend redirect: {frontend_redirect_uri}")
            if custom_data:
                logger.info(f"  Custom data: {custom_data}")
            logger.info(f"  State is self-contained (no server storage, works without cookies)")
            
            # Pass our custom state to Authlib
            # Authlib will also store it in session, but we don't rely on that
            return oauth_clients.google.authorize_redirect(redirect_uri=backend_callback_uri, state=state)
        except Exception as e:
            logger.error(f"Error in google_login: {e}")
            return jsonify({'error': str(e)}), 500

    def google_callback(self):
        try:
            # Get state from callback URL
            state = request.args.get('state')
            if not state:
                raise ValueError("No state parameter in callback")
            
            # Retrieve redirect_uri and custom_data from state (stateless!)
            state_data = self.stateless_handler.get_state_data(state)
            if not state_data:
                raise ValueError("State not found or expired (OAuth session timeout)")
            
            redirect_uri = state_data.get('redirect_uri')
            custom_data = state_data.get('custom_data', {})
            
            logger.info(f"[StatelessOAuth] Google callback received:")
            logger.info(f"  State verified (self-contained): {state[:20]}...")
            logger.info(f"  Frontend redirect: {redirect_uri}")
            if custom_data:
                logger.info(f"  Custom data: {custom_data}")
            
            # BYPASS Authlib's session-based state verification
            # Instead, manually exchange the authorization code for tokens
            code = request.args.get('code')
            if not code:
                raise ValueError("No authorization code in callback")
            
            # Manual token exchange (bypassing Authlib's authorize_access_token)
            token_endpoint = 'https://oauth2.googleapis.com/token'
            
            token_response = requests.post(token_endpoint, data={
                'code': code,
                'client_id': oauth_clients.google.client_id,
                'client_secret': oauth_clients.google.client_secret,
                'redirect_uri': _get_callback_uri(self.blueprint_name, 'google_callback_authsvc'),
                'grant_type': 'authorization_code'
            })
            
            if token_response.status_code != 200:
                raise ValueError(f"Token exchange failed: {token_response.text}")
            
            token_data = token_response.json()
            access_token = token_data.get('access_token')
            
            # Fetch user info using access token
            userinfo_endpoint = 'https://www.googleapis.com/oauth2/v2/userinfo'
            userinfo_response = requests.get(
                userinfo_endpoint,
                headers={'Authorization': f'Bearer {access_token}'}
            )
            
            if userinfo_response.status_code != 200:
                raise ValueError(f"Failed to fetch user info: {userinfo_response.text}")
            
            user_info = userinfo_response.json()
            logger.info(f"[StatelessOAuth] Successfully fetched user info for: {user_info.get('email')}")

            create_attempted = {"value": False}

            def _lookup_or_create_google_user():
                user = self.user_data_access.find_user_by_email(user_info['email'])
                if user is not None:
                    if create_attempted["value"]:
                        # The previous attempt's create_user() may have
                        # committed before an OperationalError fired on/after
                        # that same commit (a lost acknowledgement, not a
                        # lost write) - this find now sees that row and
                        # reports it as pre-existing. Not a regression (the
                        # pre-retry behavior for this same race was a hard
                        # 500 on the same request, so is_new_user never fired
                        # true for it either) but worth being able to see,
                        # since registration_hooks.py's welcome-email/promo
                        # grant depends on is_new_user being correct.
                        logger.warning(
                            f"[StatelessOAuth] {user_info['email']} found after a prior "
                            f"create attempt failed with a transient DB error in this same "
                            f"request - likely a lost commit acknowledgement. Reporting "
                            f"is_new_user=False; this user may not get their welcome email "
                            f"or promo trial grant."
                        )
                    return user, False
                create_attempted["value"] = True
                user_data = {
                    'email': user_info['email'],
                    'provider': 'google',
                    'role_id': 2,
                    'first_name': user_info.get('given_name', ''),
                    'last_name': user_info.get('family_name', ''),
                    'is_verified': True
                }
                return _find_or_create_oauth_user(
                    self.user_data_access, user_info['email'], user_data
                )

            user, is_new_user = _call_with_db_retry(
                _lookup_or_create_google_user, self.user_data_access
            )

            # Store OAuth identity in Flask g context for after_request hooks
            # UNCONDITIONALLY - not just when custom_data (a promo code, in
            # practice) is present. This used to be gated on `if custom_data:`,
            # which silently meant the common case (a plain OAuth signup with
            # no promo link) never set g.oauth_user_email at all - consuming
            # apps' after_request hooks that key off it (welcome email,
            # backend signup analytics) never fired for that majority case,
            # contradicting this very comment's own stated intent ("apps can
            # use this... regardless of whether a promo code was passed").
            # g.oauth_custom_data stays None when there's genuinely nothing to
            # apply; the downstream promo handler already treats that as
            # "no promo code provided" and no-ops correctly.
            from flask import g
            g.oauth_user_email = user_info['email']
            g.oauth_custom_data = custom_data
            g.oauth_is_new_user = is_new_user
            if custom_data:
                logger.info(f"[StatelessOAuth] Stored custom data for {'new' if is_new_user else 'existing'} user {user_info['email']}: {list(custom_data.keys())}")

            logger.info(f"[StatelessOAuth] OAuth successful for user: {user_info['email']}")
            return user, redirect_uri
        except Exception as e:
            # Roll back whatever this request's session was mid-transaction
            # on (e.g. a failed flush) before returning - without this, the
            # poisoned session survives into whichever request reuses it
            # next, which then fails with an unrelated-looking "transaction
            # has been rolled back due to a previous exception" error
            # instead of the real cause. Safe even when nothing is pending
            # (rollback() on a clean session is a no-op).
            try:
                self.user_data_access.db.session.rollback()
            except Exception:
                pass
            logger.error(f"Error in google_callback: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': str(e)}, 500

    def microsoft_login(self):
        try:
            # Use dynamic blueprint name for backend callback URL with HTTPS detection
            backend_callback_uri = _get_callback_uri(self.blueprint_name, 'microsoft_callback_authsvc')
            
            # Get frontend redirect URI
            frontend_redirect_uri = _resolve_redirect_uri(
                request.args.get('redirect_uri', self.post_login_redirect_url),
                self.post_login_redirect_url
            )
            
            # Collect custom data from query params
            # Skip 'redirect_uri' as it's handled separately
            custom_data = {
                key: value 
                for key, value in request.args.items() 
                if key != 'redirect_uri'
            }
            
            # Generate custom state and store redirect_uri + custom_data
            state = self.stateless_handler.save_state(
                frontend_redirect_uri, 
                custom_data=custom_data if custom_data else None
            )
            
            logger.info(f"[StatelessOAuth] Microsoft login initiated:")
            logger.info(f"  Backend callback: {backend_callback_uri}")
            logger.info(f"  Frontend redirect: {frontend_redirect_uri}")
            if custom_data:
                logger.info(f"  Custom data: {custom_data}")
            logger.info(f"  State is self-contained (no server storage, works without cookies)")
            
            # Pass our custom state to Authlib
            return oauth_clients.microsoft.authorize_redirect(redirect_uri=backend_callback_uri, state=state)
        except Exception as e:
            logger.error(f"Error in microsoft_login: {e}")
            return jsonify({'error': str(e)}), 500

    def microsoft_callback(self):
        try:
            # Get state from callback URL
            state = request.args.get('state')
            if not state:
                raise ValueError("No state parameter in callback")
            
            # Retrieve redirect_uri and custom_data from state (stateless!)
            state_data = self.stateless_handler.get_state_data(state)
            if not state_data:
                raise ValueError("State not found or expired (OAuth session timeout)")
            
            redirect_uri = state_data.get('redirect_uri')
            custom_data = state_data.get('custom_data', {})
            
            logger.info(f"[StatelessOAuth] Microsoft callback received:")
            logger.info(f"  State verified (self-contained): {state[:20]}...")
            logger.info(f"  Frontend redirect: {redirect_uri}")
            if custom_data:
                logger.info(f"  Custom data: {custom_data}")
            
            # BYPASS Authlib's session-based state verification
            # Manual token exchange for Microsoft
            code = request.args.get('code')
            if not code:
                raise ValueError("No authorization code in callback")
            
            token_endpoint = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
            
            token_response = requests.post(token_endpoint, data={
                'code': code,
                'client_id': oauth_clients.microsoft.client_id,
                'client_secret': oauth_clients.microsoft.client_secret,
                'redirect_uri': _get_callback_uri(self.blueprint_name, 'microsoft_callback_authsvc'),
                'grant_type': 'authorization_code'
            })
            
            if token_response.status_code != 200:
                raise ValueError(f"Token exchange failed: {token_response.text}")
            
            token_data = token_response.json()

            # Verify and decode the ID token. This used to skip signature
            # verification entirely (jwt.decode(..., options={"verify_signature":
            # False})) — meaning nothing here actually confirmed the token was
            # cryptographically issued by Microsoft rather than an arbitrary
            # unsigned JSON blob shaped like a JWT. Signature verification
            # against Microsoft's published JWKS, plus an audience check
            # against our own client_id, is exactly what the `openid` scope
            # exists for and what every OIDC client library does by default —
            # this only ever skipped it.
            id_token = token_data.get('id_token')
            user_info = self._verify_microsoft_id_token(id_token)

            logger.info(f"[StatelessOAuth] Successfully fetched user info for: {user_info.get('email')}")

            create_attempted = {"value": False}

            def _lookup_or_create_microsoft_user():
                user = self.user_data_access.find_user_by_email(user_info['email'])
                if user is not None:
                    if create_attempted["value"]:
                        # See the matching comment in google_callback - same
                        # lost-commit-acknowledgement race, same reasoning.
                        logger.warning(
                            f"[StatelessOAuth] {user_info['email']} found after a prior "
                            f"create attempt failed with a transient DB error in this same "
                            f"request - likely a lost commit acknowledgement. Reporting "
                            f"is_new_user=False; this user may not get their welcome email "
                            f"or promo trial grant."
                        )
                    return user, False
                create_attempted["value"] = True
                user_data = {
                    'email': user_info['email'],
                    'provider': 'microsoft',
                    'role_id': 2,
                }
                return _find_or_create_oauth_user(
                    self.user_data_access, user_info['email'], user_data
                )

            user, is_new_user = _call_with_db_retry(
                _lookup_or_create_microsoft_user, self.user_data_access
            )

            # Store OAuth identity in Flask g context for after_request hooks
            # UNCONDITIONALLY - not just when custom_data (a promo code, in
            # practice) is present. This used to be gated on `if custom_data:`,
            # which silently meant the common case (a plain OAuth signup with
            # no promo link) never set g.oauth_user_email at all - consuming
            # apps' after_request hooks that key off it (welcome email,
            # backend signup analytics) never fired for that majority case,
            # contradicting this very comment's own stated intent ("apps can
            # use this... regardless of whether a promo code was passed").
            # g.oauth_custom_data stays None when there's genuinely nothing to
            # apply; the downstream promo handler already treats that as
            # "no promo code provided" and no-ops correctly.
            from flask import g
            g.oauth_user_email = user_info['email']
            g.oauth_custom_data = custom_data
            g.oauth_is_new_user = is_new_user
            if custom_data:
                logger.info(f"[StatelessOAuth] Stored custom data for {'new' if is_new_user else 'existing'} user {user_info['email']}: {list(custom_data.keys())}")

            logger.info(f"[StatelessOAuth] OAuth successful for user: {user_info['email']}")
            return user, redirect_uri
        except Exception as e:
            # See the matching comment in google_callback's except block -
            # same reasoning, same fix.
            try:
                self.user_data_access.db.session.rollback()
            except Exception:
                pass
            logger.error(f"Error in microsoft_callback: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': str(e)}, 500
