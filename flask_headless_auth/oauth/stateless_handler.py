"""
Stateless OAuth Handler for Authlib
Works without cookies using self-contained signed state parameters
NO REDIS REQUIRED - Just uses Flask's SECRET_KEY
"""
import secrets
import json
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from flask import current_app


class StatelessOAuthStateHandler:
    """
    OAuth state handler that doesn't require Redis or sessions.
    Encodes all data (redirect_uri, nonce) into the state parameter itself.
    State is cryptographically signed to prevent tampering.
    
    This is the industry-standard approach:
    - Used by Auth0, AWS Cognito, Okta
    - No infrastructure dependencies
    - Works with or without cookies
    - Portable and scalable
    """
    
    def __init__(self, secret_key=None, max_age=600):
        """
        Initialize the stateless OAuth handler.
        
        Args:
            secret_key: Secret key for signing (uses Flask SECRET_KEY if None)
            max_age: State expiration time in seconds (default: 10 minutes)
        """
        self.secret_key = secret_key
        self.max_age = max_age
    
    def _get_serializer(self):
        """Get the URL-safe serializer for signing state"""
        secret = self.secret_key or current_app.config.get('SECRET_KEY')
        if not secret:
            raise ValueError("SECRET_KEY must be configured for OAuth")
        return URLSafeTimedSerializer(secret, salt='oauth_state')
    
    def save_state(self, redirect_uri, state=None, custom_data=None):
        """
        Create a self-contained signed state parameter.
        NO server-side storage needed - everything is in the state itself!
        
        Args:
            redirect_uri: Frontend redirect URI to encode in state
            state: Ignored (kept for backward compatibility)
            custom_data: Optional dict of custom data to pass through OAuth flow
                        (e.g., {'promo_code': 'xyz', 'referral': 'abc'})
        
        Returns:
            state: Signed state string containing all data
        """
        # Create state payload with redirect_uri and random nonce
        state_data = {
            'redirect_uri': redirect_uri,
            'nonce': secrets.token_urlsafe(16)  # CSRF protection
        }
        
        # Add custom data if provided
        if custom_data:
            state_data['custom_data'] = custom_data
        
        # Sign and serialize the state data
        serializer = self._get_serializer()
        signed_state = serializer.dumps(state_data)
        
        print(f"[SelfContainedOAuth] Created signed state (no server storage): {signed_state[:40]}...")
        if custom_data:
            print(f"[SelfContainedOAuth] State includes custom data: {list(custom_data.keys())}")
        return signed_state
    
    def get_redirect_uri(self, state):
        """
        Verify signature and decode state parameter to get redirect_uri.
        
        Args:
            state: Signed state string from OAuth callback
        
        Returns:
            redirect_uri: Decoded redirect URI
        
        Raises:
            ValueError: If state is invalid or expired
        """
        state_data = self.get_state_data(state)
        return state_data.get('redirect_uri')
    
    def get_state_data(self, state):
        """
        Verify signature and decode state parameter to get all state data.
        
        Args:
            state: Signed state string from OAuth callback
        
        Returns:
            dict: Decoded state data containing:
                  - redirect_uri: Frontend redirect URL
                  - custom_data: Dict of custom data passed through OAuth (if any)
                  - nonce: CSRF protection token
        
        Raises:
            ValueError: If state is invalid or expired
        """
        try:
            serializer = self._get_serializer()
            # Verify signature and check expiration
            state_data = serializer.loads(state, max_age=self.max_age)
            
            redirect_uri = state_data.get('redirect_uri')
            custom_data = state_data.get('custom_data', {})
            print(f"[SelfContainedOAuth] State verified and decoded: {redirect_uri}")
            if custom_data:
                print(f"[SelfContainedOAuth] State includes custom data: {list(custom_data.keys())}")
            return state_data
            
        except SignatureExpired:
            print(f"[SelfContainedOAuth] State expired (>{self.max_age}s)")
            raise ValueError("OAuth state expired. Please try logging in again.")
        except BadSignature:
            print(f"[SelfContainedOAuth] State signature invalid (possible tampering)")
            raise ValueError("Invalid OAuth state. Please try logging in again.")
        except Exception as e:
            print(f"[SelfContainedOAuth] Error decoding state: {e}")
            raise ValueError(f"Invalid OAuth state: {e}")

