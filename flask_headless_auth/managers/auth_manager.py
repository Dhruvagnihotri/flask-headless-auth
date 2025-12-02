from flask_headless_auth.interfaces import UserDataAccess
from flask import jsonify
from flask_headless_auth.managers.user_manager import UserManager
from flask_headless_auth.managers.token_manager import TokenManager
from flask_headless_auth.managers.oauth_manager import OAuthManager
import logging

logger = logging.getLogger(__name__)


class AuthManager:
    def __init__(self, user_data_access: UserDataAccess, cache=None, email_manager=None,
                 blueprint_name='authsvc', post_login_redirect_url='http://localhost:3000'):
        self.cache = cache  # Cache is optional
        self.user_manager = UserManager(user_data_access, cache=cache, email_manager=email_manager)
        self.token_manager = TokenManager(user_data_access)
        self.oauth_manager = OAuthManager(
            user_data_access, 
            blueprint_name=blueprint_name,
            post_login_redirect_url=post_login_redirect_url
        )
        self.email_manager = email_manager

    # User registration and updates are delegated to the user manager
    def register_user_authsvc(self, user_data):
        """
        Register user and auto-login with dual-token delivery.
        Returns tokens in both response body AND cookies.
        """
        logger.debug(f"Starting registration for user: {user_data.get('email', 'unknown')}")
        result = self.user_manager.register_user(user_data)
        logger.debug(f"Registration result type: {type(result)}")
        
        # If registration was successful, generate tokens for auto-login
        if isinstance(result, dict) and result.get('status') == 201 and result.get('user'):
            logger.info(f"Registration successful, generating tokens for user: {result['user']['email']}")
            user = result['user']
            
            # Generate tokens using dual-delivery pattern (body + cookies)
            token_response = self.token_manager.generate_token_and_set_cookies(user)
            logger.debug("Token response generated with dual-delivery")
            
            # Get the response data and merge with registration message
            response_data = token_response.get_json()
            response_data['message'] = result['message']
            
            # Create new response with updated data
            from flask import make_response, jsonify
            new_response = make_response(jsonify(response_data), 201)
            
            # Copy ALL Set-Cookie headers from token response (critical for dual-delivery)
            for header_name, header_value in token_response.headers:
                if header_name.lower() == 'set-cookie':
                    new_response.headers.add('Set-Cookie', header_value)
            
            logger.debug("Final response created with tokens in body + cookies")
            return new_response
        
        # If registration failed or returned different format, return as-is
        logger.warning("Registration failed or unexpected format")
        return result

    def update_user_authsvc(self, user_id, user_data):
        return self.user_manager.update_user(user_id, user_data)

    # Login and token management are delegated to the token manager
    def login_user_authsvc(self, user_data):
        return self.user_manager.login_user(user_data)

    def generate_token_and_set_cookies(self, user):
        return self.token_manager.generate_token_and_set_cookies(user)
    
    def generate_token_and_redirect(self, user, redirect_uri):
        return self.token_manager.generate_token_and_redirect(user, redirect_uri)

    def refresh_token_and_set_cookies(self, user):
        return self.token_manager.refresh_token_and_set_cookies(user)

    def blacklist_token_authsvc(self):
        return self.token_manager.blacklist_token_authsvc()

    def verify_mfa_authsvc(self, user, token):
        return self.token_manager.verify_mfa_authsvc(user, token)

    # OAuth management is handled by the OAuth manager
    def google_login_authsvc(self):
        return self.oauth_manager.google_login()

    def google_callback_authsvc(self):
        # Returns user, redirect_uri (cookies detected via header in route)
        return self.oauth_manager.google_callback()

    def microsoft_login_authsvc(self):
        return self.oauth_manager.microsoft_login()

    def microsoft_callback_authsvc(self):
        return self.oauth_manager.microsoft_callback()

    # Password reset request is still a user-related task
    def request_password_reset_authsvc(self, email):
        return self.user_manager.request_password_reset(email)
    
    def confirm_email(self, token):
        return self.user_manager.confirm_email(token)
