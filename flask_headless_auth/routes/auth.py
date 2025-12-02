"""
flask_headless_auth.routes.auth
~~~~~~~~~~~~~~~~~~~~~~~~~~

Authentication routes blueprint.
"""

from flask import Blueprint, request, jsonify, make_response, Response
from flask_jwt_extended import jwt_required, get_jwt_identity, unset_jwt_cookies, get_jwt
from flask_headless_auth.managers import AuthManager
from flask_headless_auth.data_access import SQLAlchemyUserRepository
from flask_headless_auth.extensions import get_cache

cache = get_cache()


def create_auth_blueprint(user_model, blacklisted_token_model, mfa_token_model,
                          password_reset_token_model, user_activity_log_model,
                          cache=None, email_manager=None, blueprint_name='authsvc',
                          post_login_redirect_url='http://localhost:3000'):
    """
    Create and return the auth blueprint.
    
    Args:
        user_model: User model class
        blacklisted_token_model: BlacklistedToken model class
        mfa_token_model: MFAToken model class
        password_reset_token_model: PasswordResetToken model class
        user_activity_log_model: UserActivityLog model class
        cache: Optional cache instance for performance optimization
        email_manager: Optional email manager instance
        blueprint_name: Name for the blueprint
        post_login_redirect_url: Default frontend URL for OAuth redirects
    """
    # Initialize the Blueprint for the auth service
    authsvc = Blueprint(blueprint_name, __name__)
    
    # Initialize the data access layer with model classes
    user_data_access = SQLAlchemyUserRepository(
        user_model=user_model,
        blacklisted_token_model=blacklisted_token_model,
        mfa_token_model=mfa_token_model,
        password_reset_token_model=password_reset_token_model,
        user_activity_log_model=user_activity_log_model
    )
    auth_manager = AuthManager(
        user_data_access, 
        cache=cache, 
        email_manager=email_manager,
        blueprint_name=blueprint_name,
        post_login_redirect_url=post_login_redirect_url
    )

    # Email/Password Registration
    @authsvc.route('/register', methods=['POST'])
    def register_authsvc():
        user_data = request.get_json()
        return auth_manager.register_user_authsvc(user_data)
    
    # Email/Password Login Route
    @authsvc.route('/login', methods=['POST'])
    def login_authsvc():
        user_data = request.get_json()
        result = auth_manager.login_user_authsvc(user_data)
        
        if result.get('error'):
            return jsonify(result), result.get('status', 401)
        
        user = result['user']
    
        # Optional: Check if Multi-Factor Authentication (MFA) is enabled
        if user["mfa_enabled"]:
            return jsonify({'message': 'MFA token sent to your registered contact'}), 200
    
        # Generate tokens and set them as HttpOnly cookies
        # Cookie detection is centralized in TokenManager.are_cookies_allowed()
        return auth_manager.generate_token_and_set_cookies(user)
    
    # Google SSO Login
    @authsvc.route('/login/google', methods=['GET'])
    def login_google_authsvc():
        return auth_manager.google_login_authsvc()
    
    # Google SSO Callback
    @authsvc.route('/auth/google/callback', methods=['GET'])
    def google_callback_authsvc():
        """
        Google OAuth callback - uses dual-token delivery.
        No cookie detection needed - always sends tokens in URL + cookies.
        Frontend tests naturally and chooses storage strategy.
        """
        user, redirect_uri = auth_manager.google_callback_authsvc()
        if isinstance(user, dict) and 'error' in user:
            return jsonify(user), 500
    
        # Generate tokens and redirect (always sends both URL + cookies)
        return auth_manager.generate_token_and_redirect(user, redirect_uri)
    
    # Microsoft SSO Login
    @authsvc.route('/login/microsoft', methods=['GET'])
    def login_microsoft_authsvc():
        return auth_manager.microsoft_login_authsvc()
    
    # Microsoft SSO Callback
    @authsvc.route('/auth/microsoft/callback', methods=['GET'])
    def microsoft_callback_authsvc():
        """
        Microsoft OAuth callback - uses dual-token delivery.
        No cookie detection needed - always sends tokens in URL + cookies.
        Frontend tests naturally and chooses storage strategy.
        """
        user, redirect_uri = auth_manager.microsoft_callback_authsvc()
        if isinstance(user, dict) and 'error' in user:
            return jsonify(user), 500
    
        # Generate tokens and redirect (always sends both URL + cookies)
        return auth_manager.generate_token_and_redirect(user, redirect_uri)
    
    # Verify MFA Token
    @authsvc.route('/verify-mfa', methods=['POST'])
    def verify_mfa_authsvc():
        data = request.get_json()
        email = data.get('email')
        token = data.get('token')
        user = user_data_access.find_user_by_email(email)
        if not user:
            return jsonify({'error': 'User not found'}), 404
    
        # Verify MFA token
        if auth_manager.verify_mfa_authsvc(user, token):
            return auth_manager.generate_token_and_set_cookies(user)
        else:
            return jsonify({'error': 'Invalid MFA token'}), 400
    
    # Request Password Reset
    @authsvc.route('/request-password-reset', methods=['POST'])
    def request_password_reset_authsvc():
        data = request.get_json()
        email = data.get('email')
        return auth_manager.request_password_reset_authsvc(email)
    
    # Access Protected Route
    @authsvc.route('/protected', methods=['GET'])
    @jwt_required()
    def protected_authsvc():
        current_user_email = get_jwt_identity()  # string
        claims = get_jwt()  # dict with 'id', 'role', etc.
        return jsonify({
            "msg": f"Welcome, {current_user_email}!",
            "user_id": claims.get("id"),
            "role": claims.get("role")
        }), 200
    
    # Refresh Token Endpoint
    @authsvc.route('/token/refresh', methods=['POST'])
    @jwt_required(refresh=True)
    def refresh():
        try:
            identity = get_jwt_identity()  # string (email)
            user = user_data_access.find_user_by_email(identity)
            return auth_manager.refresh_token_and_set_cookies(user)
        except Exception as e:
            print(f"Error refreshing token: {e}")
            return jsonify({'error': 'Error refreshing token: ' + str(e)}), 500
    
    # Logout and Blacklist Token
    @authsvc.route('/logout', methods=['POST'])
    @jwt_required()
    def logout_authsvc():
        current_user_email = get_jwt_identity()  # string (email)
        auth_manager.blacklist_token_authsvc()
        # Clear user-specific cache
        cache.delete(f"user_{current_user_email}")
        response = make_response(jsonify({"msg": "Successfully logged out"}))
        unset_jwt_cookies(response)
        return response
    
    # Check Authentication Route
    @authsvc.route('/check-auth', methods=['GET'])
    @jwt_required()  # Requires the user to be authenticated
    def check_auth():
        try:
            current_user_email = get_jwt_identity()  # string (email)
            claims = get_jwt()
            
            return jsonify({
                "msg": "User is authenticated",
                "user": {
                    "email": current_user_email,
                    "id": claims.get("id"),
                    "role": claims.get("role")
                }
            }), 200
        except Exception as e:
            print(f"Error in check-auth: {e}")
            return jsonify({"error": "Error checking authentication", "details": str(e)}), 500
    
    # Get Logged-In User Details
    @authsvc.route('/user/@me', methods=['GET'])
    @jwt_required()  # Requires the user to be authenticated
    def get_logged_in_user():
        try:
            current_user_email = get_jwt_identity()  # string (email)
            # Check if user details are in cache
            cached_user = cache.get(f"user_{current_user_email}")
            if cached_user:
                return jsonify({"user": cached_user}), 200
            user = user_data_access.find_user_by_email(current_user_email)
            if not user:
                return jsonify({"error": "User not found"}), 404
            user_details = {
                "id": user["id"],
                "email": user["email"],
                "roles": user["role_id"],  # Example if user has roles associated
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "phone_number": user["phone_number"],
                "is_verified": user["is_verified"],
                "bio": user.get("bio"),
                "occupation": user.get("occupation"),
                "date_of_birth": user.get("date_of_birth").isoformat() if user.get("date_of_birth") else None,
                "address": user.get("address"),
                "city": user.get("city"),
                "state": user.get("state"),
                "country": user.get("country"),
                "zip_code": user.get("zip_code"),
                "profile_picture": user.get("profile_picture")
            }
            # Cache the user details only on successful retrieval
            cache.set(f"user_{current_user_email}", user_details, timeout=300)  # Cache for 5 minutes
            return jsonify({"user": user_details}), 200
        except Exception as e:
            print(f"Error in fetching logged-in user details: {e}")
            return jsonify({"error": "Error fetching user details", "details": str(e)}), 500
    
    # Update User Route
    @authsvc.route('/update_user', methods=['POST'])
    @jwt_required()
    def update_user():
        current_user_email = get_jwt_identity()  # string (email)
        user_data = request.get_json()
        response = auth_manager.update_user_authsvc(current_user_email, user_data)
        cache.delete(f"user_{current_user_email}")
        return response
    
    @authsvc.route('/confirm/<token>', methods=['GET'])
    def confirm_email(token):
        result = auth_manager.confirm_email(token)
        # If it's not a Response object, handle it as before
        if isinstance(result, tuple):
            response, status_code = result
        else:
            response = result
            status_code = result.get('status', 200)
    
        if status_code == 200:
            response_data = response.get_json()
            user_email = response_data.get('user', {}).get('email')
            if user_email:
                cache.delete(f"user_{user_email}")
        
        if isinstance(result, tuple):
            return result
        
        return jsonify(response), status_code
    
    @authsvc.route('/resend-verification-email', methods=['POST'])
    @jwt_required()
    def resend_verification_email():
        # Send verification email
        current_user_email = get_jwt_identity()  # string (email)
        user = user_data_access.find_user_by_email(current_user_email)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        if user['is_verified']:
            return jsonify({'message': 'User is already verified'}), 200
        try:
            auth_manager.user_manager.email_manager.send_verification_email(user['email'])
            user_data_access.log_user_activity(user['id'], "Verification email resent")
            return jsonify({'message': 'Verification email sent successfully'}), 200
        except Exception as e:
            print(f"Error sending verification email: {e}")
            return jsonify({'error': 'Failed to send verification email'}), 500
    
    # Upload Profile Picture
    @authsvc.route('/upload-profile-picture', methods=['POST'])
    @jwt_required()
    def upload_profile_picture():
        try:
            current_user_email = get_jwt_identity()
            user = user_data_access.find_user_by_email(current_user_email)
    
            if not user:
                return jsonify({'error': 'User not found'}), 404
    
            # Check if file was uploaded
            if 'profile_picture' not in request.files:
                return jsonify({'error': 'No file uploaded'}), 400
    
            file = request.files['profile_picture']
    
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400
    
            # Security: Sanitize filename to prevent path traversal
            import os
            import re
            safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '', file.filename or 'image')
    
            # Validate file type more securely
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
            allowed_mime_types = {
                'image/png', 'image/jpeg', 'image/jpg',
                'image/gif', 'image/webp'
            }
    
            file_extension = None
            if '.' in safe_filename:
                file_extension = safe_filename.rsplit('.', 1)[1].lower()
    
            # Check both extension and MIME type for security
            if (not file_extension or
                file_extension not in allowed_extensions or
                file.mimetype not in allowed_mime_types):
                return jsonify({'error': 'Invalid file type. Please upload a valid image (PNG, JPG, GIF, WebP).'}), 400
    
            # Validate file size (5MB limit)
            file.seek(0, 2)  # Seek to end
            size = file.tell()  # Get position (file size)
            file.seek(0)  # Reset to beginning
    
            if size > 5 * 1024 * 1024:  # 5MB in bytes
                return jsonify({'error': 'File too large. Maximum size is 5MB.'}), 400
    
            # Additional security: Check for minimum file size (to prevent empty files)
            if size < 100:  # 100 bytes minimum
                return jsonify({'error': 'File too small. Please upload a valid image.'}), 400
    
            # Rate limiting check (optional: implement if needed)
            # You could add Redis-based rate limiting here
    
            # TODO: Implement actual file storage (AWS S3, local storage, etc.)
            # For now, we'll return a placeholder URL
            # In production, you would:
            # 1. Scan the file for malware
            # 2. Process/optimize the image
            # 3. Store in secure location (S3, CDN)
            # 4. Generate secure URLs
    
            import uuid
            import hashlib
    
            # Generate secure unique filename
            file_hash = hashlib.md5(f"{user['id']}{uuid.uuid4().hex}".encode()).hexdigest()
            unique_filename = f"{file_hash}.{file_extension}"
    
            # For now, just return a mock URL - in production you'd save to storage
            profile_picture_url = f"/uploads/profiles/{unique_filename}"
    
            # Update user's profile picture URL in database
            update_result = auth_manager.update_user_authsvc(current_user_email, {
                'profile_picture': profile_picture_url
            })
    
            # Clear user cache
            cache.delete(f"user_{current_user_email}")
    
            # Log the activity for security audit
            user_data_access.log_user_activity(user['id'], "Profile picture uploaded")
    
            return jsonify({
                'message': 'Profile picture uploaded successfully',
                'profile_picture_url': profile_picture_url
            }), 200
    
        except Exception as e:
            print(f"Error uploading profile picture: {e}")
            # Log the error for security monitoring
            user_data_access.log_user_activity(user.get('id') if 'user' in locals() else None,
                                             f"Profile picture upload failed: {str(e)}")
            return jsonify({'error': 'Failed to upload profile picture'}), 500
    

    return authsvc
