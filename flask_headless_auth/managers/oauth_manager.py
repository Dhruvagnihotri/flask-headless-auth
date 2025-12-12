import base64
import json
import logging
import requests
from flask import request, url_for, jsonify, session
from flask_headless_auth.oauth.providers import oauth_clients
from flask_headless_auth.interfaces import UserDataAccess
from flask_headless_auth.oauth.stateless_handler import StatelessOAuthStateHandler

logger = logging.getLogger(__name__)


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

    def google_login(self):
        try:
            # Use dynamic blueprint name for backend callback URL with HTTPS detection
            backend_callback_uri = _get_callback_uri(self.blueprint_name, 'google_callback_authsvc')
            
            # Get frontend redirect URI
            frontend_redirect_uri = request.args.get('redirect_uri', self.post_login_redirect_url)
            
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

            user = self.user_data_access.find_user_by_email(user_info['email'])
            is_new_user = user is None
            
            if not user:
                user_data = {
                    'email': user_info['email'],
                    'provider': 'google',
                    'role_id': 2,
                    'first_name': user_info.get('given_name', ''),
                    'last_name': user_info.get('family_name', ''),
                    'is_verified': True
                }
                user = self.user_data_access.create_user(user_data)

            # Store custom data in Flask g context for after_request hooks
            # Apps can use this to access custom data passed through OAuth
            if is_new_user and custom_data:
                from flask import g
                g.oauth_user_email = user_info['email']
                g.oauth_custom_data = custom_data
                logger.info(f"[StatelessOAuth] Stored custom data for new user {user_info['email']}: {list(custom_data.keys())}")

            logger.info(f"[StatelessOAuth] OAuth successful for user: {user_info['email']}")
            return user, redirect_uri
        except Exception as e:
            logger.error(f"Error in google_callback: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': str(e)}, 500

    def microsoft_login(self):
        try:
            # Use dynamic blueprint name for backend callback URL with HTTPS detection
            backend_callback_uri = _get_callback_uri(self.blueprint_name, 'microsoft_callback_authsvc')
            
            # Get frontend redirect URI
            frontend_redirect_uri = request.args.get('redirect_uri', self.post_login_redirect_url)
            
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
            
            # Decode the ID token to get user info
            import jwt
            id_token = token_data.get('id_token')
            user_info = jwt.decode(id_token, options={"verify_signature": False})
            
            logger.info(f"[StatelessOAuth] Successfully fetched user info for: {user_info.get('email')}")

            user = self.user_data_access.find_user_by_email(user_info['email'])
            is_new_user = user is None
            
            if not user:
                user_data = {
                    'email': user_info['email'],
                    'provider': 'microsoft',
                    'role_id': 2,
                }
                user = self.user_data_access.create_user(user_data)

            # Store custom data in Flask g context for after_request hooks
            # Apps can use this to access custom data passed through OAuth
            if is_new_user and custom_data:
                from flask import g
                g.oauth_user_email = user_info['email']
                g.oauth_custom_data = custom_data
                logger.info(f"[StatelessOAuth] Stored custom data for new user {user_info['email']}: {list(custom_data.keys())}")

            logger.info(f"[StatelessOAuth] OAuth successful for user: {user_info['email']}")
            return user, redirect_uri
        except Exception as e:
            logger.error(f"Error in microsoft_callback: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': str(e)}, 500
