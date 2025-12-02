from flask_jwt_extended import (
    create_access_token, create_refresh_token, get_jwt, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, verify_jwt_in_request
)
from flask import jsonify, make_response, request, current_app
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import logging
from flask_headless_auth.interfaces import UserDataAccess

logger = logging.getLogger(__name__)

class TokenManager:
    def __init__(self, user_data_access: UserDataAccess):
        self.user_data_access = user_data_access

    def generate_token_authsvc(self, user, additional_claims=None):
        logger.debug(f"Generating token for user ID: {user.get('id')}")
        identity = user['email']
        claims = {
            'id': user['id'], 
            'role': user.get('role_id', 2),  # Default role_id = 2 if not present
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'email': user['email']
        }
        if additional_claims:
            claims.update(additional_claims)
        access_token = create_access_token(identity=identity, additional_claims=claims)
        refresh_token = create_refresh_token(identity=identity, additional_claims=claims)
        return {'access_token': access_token, 'refresh_token': refresh_token}

    @staticmethod
    def is_browser_request():
        """Check if request is from a browser (vs API client like Postman)."""
        user_agent = request.headers.get('User-Agent', '').lower()
        browsers = ['chrome', 'firefox', 'safari', 'edge', 'opera', 'trident', 'msie']
        return any(browser in user_agent for browser in browsers)

    def generate_token_and_set_cookies(self, user):
        """
        Configurable token delivery with secure defaults.
        
        Three modes (configured via AUTHSVC_TOKEN_DELIVERY):
        
        1. 'cookies_only' (DEFAULT - Most Secure):
           - Browser clients: Tokens via httpOnly cookies ONLY (XSS-proof)
           - API clients: Tokens in response body
           - No localStorage, no XSS attack surface
           - Used by: Most banks, fintech, healthcare apps
        
        2. 'body_only' (For APIs):
           - Tokens in response body ONLY
           - No cookies set
           - Used by: Mobile apps, API-first services
        
        3. 'dual' (Flexible - Backwards Compatible):
           - Tokens in BOTH body AND cookies
           - Frontend chooses which to use
           - Used by: Apps supporting cookie-blocked users
        
        Args:
            user: User dict with id, email, role_id, etc.
            
        Returns:
            Flask Response with tokens based on configuration
        """
        tokens = self.generate_token_authsvc(user)
        is_browser = self.is_browser_request()
        
        # Get delivery mode from config (default: cookies_only)
        delivery_mode = current_app.config.get('AUTHSVC_TOKEN_DELIVERY', 'cookies_only')
        
        # MODE 1: Cookies Only (Industry Standard - Most Secure)
        if delivery_mode == 'cookies_only':
            response_data = {
                'msg': 'Login successful',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'role': user.get('role_id', 2)
                }
                # NO tokens in body for browser clients!
            }
            response = make_response(jsonify(response_data))
            
            if is_browser:
                # Browser: Secure httpOnly cookies only
                logger.info("cookies_only mode: Setting httpOnly cookies (secure)")
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])
            else:
                # Non-browser (Postman, mobile): Need tokens in body
                logger.info("cookies_only mode: Non-browser client, tokens in body")
                response_data['access_token'] = tokens['access_token']
                response_data['refresh_token'] = tokens['refresh_token']
                response = make_response(jsonify(response_data))
        
        # MODE 2: Body Only (For APIs, Mobile Apps)
        elif delivery_mode == 'body_only':
            logger.info("body_only mode: Tokens in response body")
            response_data = {
                'msg': 'Login successful',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            response = make_response(jsonify(response_data))
            # No cookies set
        
        # MODE 3: Dual Delivery (Backwards Compatible, Flexible)
        elif delivery_mode == 'dual':
            logger.info("dual mode: Tokens in BOTH body AND cookies")
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
            # Invalid mode - log error and default to cookies_only
            logger.error(f"Invalid AUTHSVC_TOKEN_DELIVERY mode: {delivery_mode}. Using 'cookies_only'")
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

        return response



    def refresh_token_and_set_cookies(self, user):
        """
        Refresh tokens using the same delivery mode as login.
        
        Respects AUTHSVC_TOKEN_DELIVERY configuration:
        - cookies_only: Refreshed tokens via cookies (browser) or body (API)
        - body_only: Refreshed tokens in body only
        - dual: Refreshed tokens in both body and cookies
        
        Args:
            user: User dict with id, email, role_id, etc.
            
        Returns:
            Flask Response with refreshed tokens based on configuration
        """
        tokens = self.generate_token_authsvc(user)
        is_browser = self.is_browser_request()
        
        # Get delivery mode from config (default: cookies_only)
        delivery_mode = current_app.config.get('AUTHSVC_TOKEN_DELIVERY', 'cookies_only')
        
        # MODE 1: Cookies Only (Industry Standard)
        if delivery_mode == 'cookies_only':
            response_data = {
                'msg': 'Token refreshed successfully',
            }
            response = make_response(jsonify(response_data))
            
            if is_browser:
                logger.info("cookies_only mode: Refreshing via httpOnly cookies")
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])
            else:
                logger.info("cookies_only mode: Non-browser refresh, tokens in body")
                response_data['access_token'] = tokens['access_token']
                response_data['refresh_token'] = tokens['refresh_token']
                response = make_response(jsonify(response_data))
        
        # MODE 2: Body Only (For APIs)
        elif delivery_mode == 'body_only':
            logger.info("body_only mode: Refreshed tokens in body")
            response_data = {
                'msg': 'Token refreshed successfully',
                'access_token': tokens['access_token'],
                'refresh_token': tokens['refresh_token']
            }
            response = make_response(jsonify(response_data))
        
        # MODE 3: Dual Delivery (Backwards Compatible)
        elif delivery_mode == 'dual':
            logger.info("dual mode: Refreshed tokens in BOTH body AND cookies")
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
            # Invalid mode - default to cookies_only
            logger.error(f"Invalid AUTHSVC_TOKEN_DELIVERY mode: {delivery_mode}. Using 'cookies_only'")
            response_data = {'msg': 'Token refreshed successfully'}
            response = make_response(jsonify(response_data))
            if is_browser:
                set_access_cookies(response, tokens['access_token'])
                set_refresh_cookies(response, tokens['refresh_token'])

        return response



    def generate_token_and_redirect(self, user, redirect_uri):
        """
        OAuth callback token delivery respecting AUTHSVC_TOKEN_DELIVERY configuration.
        
        Three modes:
        1. 'cookies_only': Tokens via cookies, NO URL parameters (most secure)
        2. 'body_only': Tokens in URL parameters only (unusual for OAuth)
        3. 'dual': Tokens in BOTH URL + cookies (backwards compatible)
        
        Args:
            user: User dict with id, email, role_id, etc.
            redirect_uri: Frontend URL to redirect to after authentication
            
        Returns:
            Flask Response with 302 redirect
        """
        try:
            tokens = self.generate_token_authsvc(user)
            is_browser = self.is_browser_request()
            
            # Get delivery mode from config (default: cookies_only)
            delivery_mode = current_app.config.get('AUTHSVC_TOKEN_DELIVERY', 'cookies_only')
            
            # MODE 1: Cookies Only (Industry Standard)
            if delivery_mode == 'cookies_only':
                logger.info("cookies_only mode: OAuth tokens via cookies, NO URL params")
                # Clean redirect - no tokens in URL
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                
                if is_browser:
                    set_access_cookies(response, tokens['access_token'])
                    set_refresh_cookies(response, tokens['refresh_token'])
                else:
                    # Non-browser OAuth is rare, but append tokens to URL as fallback
                    logger.warning("Non-browser OAuth client - appending tokens to URL")
                    redirect_uri = self._append_tokens_to_url(redirect_uri, tokens)
                    response.headers['Location'] = redirect_uri
            
            # MODE 2: Body Only (URL parameters for OAuth)
            elif delivery_mode == 'body_only':
                logger.info("body_only mode: OAuth tokens in URL parameters")
                redirect_uri = self._append_tokens_to_url(redirect_uri, tokens)
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                # No cookies set
            
            # MODE 3: Dual (Backwards Compatible)
            elif delivery_mode == 'dual':
                logger.info("dual mode: OAuth tokens in BOTH URL AND cookies")
                redirect_uri = self._append_tokens_to_url(redirect_uri, tokens)
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                
                if is_browser:
                    set_access_cookies(response, tokens['access_token'])
                    set_refresh_cookies(response, tokens['refresh_token'])
            
            else:
                # Invalid mode - default to cookies_only
                logger.error(f"Invalid AUTHSVC_TOKEN_DELIVERY mode: {delivery_mode}. Using 'cookies_only'")
                response = make_response('', 302)
                response.headers['Location'] = redirect_uri
                if is_browser:
                    set_access_cookies(response, tokens['access_token'])
                    set_refresh_cookies(response, tokens['refresh_token'])
            
            return response
            
        except Exception as e:
            logger.error(f"Error in generate_token_and_redirect: {e}")
            # Return error redirect
            error_response = make_response('', 302)
            error_response.headers['Location'] = f"{redirect_uri}?error=token_generation_failed"
            return error_response
    
    def _append_tokens_to_url(self, redirect_uri, tokens):
        """
        Helper to append tokens to redirect URL.
        
        Args:
            redirect_uri: Base URL to redirect to
            tokens: Dict with 'access_token' and 'refresh_token'
            
        Returns:
            URL string with tokens appended as query parameters
        """
        try:
            parsed_url = urlparse(redirect_uri)
            query_params = parse_qs(parsed_url.query)
            
            # Add tokens to URL parameters
            query_params['access_token'] = [tokens['access_token']]
            query_params['refresh_token'] = [tokens['refresh_token']]
            
            # Reconstruct URL with tokens
            new_query = urlencode(query_params, doseq=True)
            return urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                new_query,
                parsed_url.fragment
            ))
        except Exception as e:
            logger.error(f"Error appending tokens to URL: {e}")
            return redirect_uri  # Return original URL if parsing fails

    def blacklist_token_authsvc(self):
        try:
            verify_jwt_in_request()
            jti = get_jwt().get('jti')

            if not jti:
                return jsonify({'error': 'JWT ID not found in token.'}), 400

            if self.user_data_access.is_token_blacklisted(jti):
                return jsonify({'msg': 'Token is already blacklisted.'}), 200

            self.user_data_access.blacklist_token(jti)
            return jsonify({'msg': 'Token successfully blacklisted.'}), 200

        except Exception as e:
            logger.error(f"Error blacklisting token: {e}")
            return jsonify({'error': 'Error blacklisting token', 'details': str(e)}), 500

    def verify_mfa_authsvc(self, user, token):
        return self.user_data_access.verify_mfa_token(user['id'], token)
